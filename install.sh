#!/usr/bin/env bash
# Installazione (o aggiornamento) di fwlog su Ubuntu/Debian o Rocky/RHEL 9.
# Idempotente: si puo' rieseguire per aggiornare il codice, non sovrascrive
# configurazione e certificati.
#
#   sudo ./install.sh                 installazione normale
#   sudo FORCE=1 ./install.sh         anche se /srv/fwlog non e' un disco separato
#   sudo WEB_PORT=11443 ./install.sh  altra porta per la dashboard (default 10443,
#                                     solo alla prima installazione)
set -euo pipefail

APP=/opt/fwlog
DATA=/srv/fwlog
ETC=/etc/fwlog
ENV_FILE=$ETC/fwlog.env
SRC=$(cd "$(dirname "$0")" && pwd)

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mATTENZIONE:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERRORE:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "eseguire come root (sudo ./install.sh)"
WEB_PORT_SET=${WEB_PORT:+1}
WEB_PORT=${WEB_PORT:-10443}
case $WEB_PORT in ''|*[!0-9]*) die "WEB_PORT non valida: $WEB_PORT" ;; esac
[ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] && [ "$WEB_PORT" -ne 514 ] \
    || die "WEB_PORT deve essere tra 1 e 65535 e diversa da 514"
[ -f "$SRC/fwlog.py" ] && [ -f "$SRC/static/index.html" ] && [ -f "$SRC/fwlog.service" ] \
    || die "eseguire dalla cartella del repository (mancano fwlog.py, static/ o fwlog.service)"

# 1. pacchetti
info "Installo python3 e openssl"
if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 openssl >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3 openssl >/dev/null
else
    die "gestore pacchetti non supportato (servono apt-get o dnf)"
fi

# 2. utente di sistema
if ! id fwlog >/dev/null 2>&1; then
    info "Creo l'utente di sistema fwlog"
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin fwlog
fi

# 4. il disco dati deve essere montato (prima di toccare /srv/fwlog)
if ! mountpoint -q "$DATA"; then
    if [ "${FORCE:-0}" = "1" ]; then
        warn "$DATA non e' un mount point: i log finiranno sul disco di sistema (FORCE=1)."
        warn "Con FORCE=1 il servizio non richiede il mount: modifico la unit di conseguenza."
    else
        die "$DATA non e' un mount point. Preparare e montare il disco dati (vedi README.md,
       'Preparazione del secondo disco'), oppure rieseguire con FORCE=1 per usare il disco di sistema."
    fi
fi

# 3. codice (root, non scrivibile da fwlog)
info "Copio il programma in $APP"
install -d -o root -g root -m 0755 "$APP" "$APP/static"
install -o root -g root -m 0755 "$SRC/fwlog.py" "$APP/fwlog.py"
install -o root -g root -m 0644 "$SRC/static/index.html" "$APP/static/index.html"
for f in README.md test-sender.py; do
    [ -f "$SRC/$f" ] && install -o root -g root -m 0644 "$SRC/$f" "$APP/$f"
done
rm -rf "$APP/__pycache__"

# 5. cartelle
install -d -o fwlog -g fwlog -m 0750 "$DATA"
install -d -o root -g fwlog -m 0750 "$ETC"

# 6. certificato TLS e configurazione (mai sovrascritti)
HOST_S=$(hostname -s)
HOST_F=$(hostname -f 2>/dev/null || hostname)
IPS=$(hostname -I 2>/dev/null || true)
if [ ! -f "$ETC/tls.crt" ] || [ ! -f "$ETC/tls.key" ]; then
    info "Genero il certificato autofirmato"
    SAN="DNS:$HOST_S,DNS:localhost,IP:127.0.0.1"
    [ "$HOST_F" != "$HOST_S" ] && SAN="$SAN,DNS:$HOST_F"
    for ip in $IPS; do SAN="$SAN,IP:$ip"; done
    ( umask 077
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 \
          -days 3650 -subj "/CN=$HOST_S/O=fwlog" -addext "subjectAltName=$SAN" \
          -keyout "$ETC/tls.key" -out "$ETC/tls.crt" 2>/dev/null )
    chown root:fwlog "$ETC/tls.key" "$ETC/tls.crt"
    chmod 0640 "$ETC/tls.key"
    chmod 0644 "$ETC/tls.crt"
fi

NEW_PASS=""
if [ ! -f "$ENV_FILE" ]; then
    info "Creo $ENV_FILE"
    NEW_PASS=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)
    ( umask 027
      cat > "$ENV_FILE" <<EOF
# Configurazione di fwlog. Dopo una modifica: systemctl restart fwlog
FWLOG_DATA_DIR=$DATA
FWLOG_SYSLOG_BIND=0.0.0.0
# porte syslog, 0 = disattivato
FWLOG_SYSLOG_UDP=514
FWLOG_SYSLOG_TCP=514
FWLOG_WEB_BIND=0.0.0.0
FWLOG_WEB_PORT=$WEB_PORT
FWLOG_WEB_USER=admin
FWLOG_WEB_PASS=$NEW_PASS
FWLOG_TLS_CERT=$ETC/tls.crt
FWLOG_TLS_KEY=$ETC/tls.key
# giorni di conservazione dei log, 0 = senza limite (vale comunque FWLOG_MIN_FREE_GB)
FWLOG_RETENTION_DAYS=90
# sotto questo spazio libero (GB) vengono eliminati i log piu' vecchi
FWLOG_MIN_FREE_GB=2
# IP o subnet ammessi a inviare log, separati da virgola; vuoto = tutti
FWLOG_ALLOWED_SOURCES=
FWLOG_QUEUE_MAX=200000
EOF
    )
    chown root:fwlog "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
elif [ -n "$WEB_PORT_SET" ] && ! grep -q "^FWLOG_WEB_PORT=$WEB_PORT\$" "$ENV_FILE"; then
    warn "$ENV_FILE esiste gia': WEB_PORT=$WEB_PORT ignorata. Per cambiare porta"
    warn "modificare FWLOG_WEB_PORT nel file e poi: systemctl restart fwlog"
fi

# 7. buffer UDP del kernel
info "Imposto i buffer UDP del kernel"
cat > /etc/sysctl.d/90-fwlog.conf <<'EOF'
# fwlog: buffer di ricezione UDP ampi per non perdere syslog nei picchi
net.core.rmem_max=16777216
net.core.rmem_default=8388608
EOF
sysctl --system >/dev/null

# 8. servizio
info "Installo e avvio il servizio"
if [ "${FORCE:-0}" = "1" ] && ! mountpoint -q "$DATA"; then
    sed 's|^RequiresMountsFor=.*|# RequiresMountsFor disattivato da FORCE=1|' "$SRC/fwlog.service" \
        > /etc/systemd/system/fwlog.service
else
    install -o root -g root -m 0644 "$SRC/fwlog.service" /etc/systemd/system/fwlog.service
fi
chmod 0644 /etc/systemd/system/fwlog.service
systemctl daemon-reload
systemctl enable fwlog >/dev/null 2>&1
systemctl restart fwlog
sleep 2
if ! systemctl is-active --quiet fwlog; then
    journalctl -u fwlog -n 20 --no-pager >&2 || true
    die "il servizio non e' partito, vedi sopra o: journalctl -u fwlog"
fi

# 9. riepilogo
PORT=$(sed -n 's/^FWLOG_WEB_PORT=//p' "$ENV_FILE" | tail -1)
USER_W=$(sed -n 's/^FWLOG_WEB_USER=//p' "$ENV_FILE" | tail -1)
echo
info "fwlog e' attivo."
echo "    Dashboard:"
for ip in $IPS; do
    case $ip in *:*) echo "      https://[$ip]:${PORT:-10443}/" ;; *) echo "      https://$ip:${PORT:-10443}/" ;; esac
done
echo "      https://$HOST_F:${PORT:-10443}/"
echo "    Utente:   ${USER_W:-admin}"
if [ -n "$NEW_PASS" ]; then
    echo "    Password: $NEW_PASS"
    echo "    (annotala: e' salvata solo in $ENV_FILE)"
else
    echo "    Password: invariata (in $ENV_FILE)"
fi
echo "    Il certificato e' autofirmato: il browser mostrera' un avviso al primo accesso."
echo "    Firewall: inviare syslog a questo server su UDP o TCP 514."

if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -q "^Status: active"; then
    echo
    warn "ufw e' attivo. Per aprire le porte (meglio limitare alle reti dei firewall):"
    echo "    ufw allow 514/udp"
    echo "    ufw allow 514/tcp"
    echo "    ufw allow ${PORT:-10443}/tcp"
    echo "    # esempio con restrizione: ufw allow from 192.168.1.0/24 to any port 514 proto udp"
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    echo
    warn "firewalld e' attivo. Per aprire le porte (meglio limitare alle reti dei firewall):"
    echo "    firewall-cmd --permanent --add-port=514/udp --add-port=514/tcp --add-port=${PORT:-10443}/tcp"
    echo "    firewall-cmd --reload"
    echo "    # restrizioni per rete: vedi docs/INSTALL-ROCKY9.md"
fi
