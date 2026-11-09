#!/usr/bin/env bash
# Prepara la VM come template da clonare (VHDX, qcow2, template Proxmox...).
# Da eseguire come root sulla VM template, subito prima di spegnerla per la copia.
#
#   sudo ./prepara-template.sh          chiede conferma
#   sudo SI=1 ./prepara-template.sh     senza conferma
#   sudo SPEGNI=1 ./prepara-template.sh spegne la VM alla fine
#
# Rimuove cio' che deve essere unico per ogni cliente: password e certificato di
# fwlog, eventuale database di prova, machine-id e chiavi SSH. Il disco dati NON
# deve far parte del template: si aggiunge da ogni cliente, poi si esegue install.sh.
set -euo pipefail

DATA=/srv/fwlog
ETC=/etc/fwlog
SRC=$(cd "$(dirname "$0")" && pwd)

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mATTENZIONE:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERRORE:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "eseguire come root (sudo ./prepara-template.sh)"
[ -f "$SRC/install.sh" ] && [ -f "$SRC/fwlog.py" ] \
    || die "eseguire dalla cartella del repository (manca install.sh o fwlog.py)"

# il disco dati non deve far parte del template
if mountpoint -q "$DATA"; then
    die "$DATA e' montato. Il disco dati si aggiunge da ogni cliente:
       sudo systemctl stop fwlog; sudo umount $DATA
       rimuovere la riga di $DATA da /etc/fstab e scollegare il disco dalla VM."
fi
if grep -Eq "^[^#]*[[:space:]]$DATA[[:space:]]" /etc/fstab; then
    die "/etc/fstab contiene una voce per $DATA: rimuoverla (il disco del cliente avra' un altro UUID)."
fi

echo "Questa VM verra' preparata come template:"
echo "  - servizio fwlog fermato e disattivato (se installato)"
echo "  - eliminati database di prova in $DATA, $ETC/fwlog.env, certificato e chiave TLS"
echo "  - azzerati machine-id e chiavi host SSH (rigenerati al primo avvio del clone)"
echo "  - puliti cache dnf/apt, journal e cronologia della shell"
echo "Dopo, spegnere la VM e NON riavviarla prima di averla copiata."
if [ "${SI:-0}" != "1" ]; then
    read -r -p "Continuare? [s/N] " r
    case $r in s|S|si|SI|Si) ;; *) die "annullato" ;; esac
fi

# 1. fwlog: servizio, dati di prova, segreti
if systemctl cat fwlog.service >/dev/null 2>&1; then
    info "Fermo e disattivo fwlog"
    systemctl disable --now fwlog >/dev/null 2>&1 || true
fi
if [ -d "$DATA" ]; then
    info "Svuoto $DATA (sul disco di sistema)"
    find "$DATA" -mindepth 1 -delete
fi
info "Elimino password e certificato in $ETC"
rm -f "$ETC/fwlog.env" "$ETC/tls.crt" "$ETC/tls.key"

# 2. identita' della macchina
info "Azzero machine-id"
: > /etc/machine-id
if [ -f /var/lib/dbus/machine-id ] && [ ! -L /var/lib/dbus/machine-id ]; then
    rm -f /var/lib/dbus/machine-id
fi

info "Elimino le chiavi host SSH"
rm -f /etc/ssh/ssh_host_*
# Rocky/RHEL le rigenera da solo (sshd-keygen@); su Ubuntu/Debian serve una unit
if ! systemctl cat sshd-keygen@.service >/dev/null 2>&1; then
    cat > /etc/systemd/system/ssh-hostkeys.service <<'EOF'
[Unit]
Description=Rigenera le chiavi host SSH mancanti (VM clonata)
Before=ssh.service ssh.socket sshd.service
ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ssh-hostkeys.service >/dev/null 2>&1
fi

# 3. pulizia
info "Pulisco cache, journal e cronologia"
if command -v dnf >/dev/null 2>&1; then dnf clean all -q >/dev/null 2>&1 || true; fi
if command -v apt-get >/dev/null 2>&1; then apt-get clean || true; fi
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
rm -f /root/.bash_history /home/*/.bash_history
# spazio libero restituito allo storage (VHDX/qcow2 piu' piccoli)
fstrim -a >/dev/null 2>&1 || true

echo
info "Template pronto."
echo "    Repository per install.sh: $SRC"
echo "    Da controllare a mano: IP statico e hostname (vanno cambiati da ogni cliente)."
echo "    Da ogni cliente: aggiungere e montare il disco dati, poi"
echo "      cd $SRC && sudo ./install.sh"
echo "    (genera password e certificato nuovi e riattiva il servizio)."

if [ "${SPEGNI:-0}" = "1" ]; then
    info "Spengo la VM"
    poweroff
else
    echo
    warn "Spegnere ora con 'poweroff' e copiare il disco senza riavviare la VM."
fi
