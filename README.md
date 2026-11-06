# fwlog

Server syslog semplice dedicato ai **log dei firewall**, con dashboard web.

I firewall inviano syslog (UDP o TCP 514). fwlog estrae sorgente, destinazione, porte,
protocollo, azione, interfacce, zone e regola, e li salva in SQLite su un disco dedicato.
Dalla dashboard si sceglie un firewall e si filtrano i suoi log.

- Un solo file Python, sola libreria standard: niente `pip`, niente dipendenze.
- Formati riconosciuti: pfSense, OPNsense, FortiGate, Sophos Firewall, Palo Alto,
  Cisco ASA/FTD, MikroTik, SonicWall, Zyxel, iptables/UFW, UniFi e in generale i log
  `chiave=valore`. Gli altri messaggi vengono comunque salvati e sono cercabili per testo.
- Conservazione automatica (90 giorni di default, modificabile per ogni firewall),
  eliminazione dei log dalla dashboard e protezione del disco pieno.

Non è un SIEM: niente correlazione, alert o gestione utenti.

---

## Indice

1. [Preparazione del secondo disco](#1-preparazione-del-secondo-disco)
2. [Installazione](#2-installazione)
3. [Primo accesso](#3-primo-accesso)
4. [Configurazione dei firewall](#4-configurazione-dei-firewall)
5. [Uso dei filtri](#5-uso-dei-filtri)
6. [Configurazione](#6-configurazione)
7. [Spazio su disco](#7-spazio-su-disco)
8. [Gestione](#8-gestione)
9. [Test con test-sender.py](#9-test-con-test-senderpy)
10. [Limiti noti](#10-limiti-noti)

---

## 1. Preparazione del secondo disco

I log vanno **solo** sul secondo disco, montato su `/srv/fwlog`. Il servizio non parte
se il disco non è montato, così il disco di sistema non si riempie mai.

> **Attenzione:** `mkfs` cancella tutto il contenuto del disco. Controllare due volte
> il nome del dispositivo con `lsblk`.

### In Proxmox

1. Seleziona la VM → **Hardware** → **Aggiungi** → **Disco rigido**.
2. Bus **SCSI**, dimensione a piacere (es. 100 GB). Con storage thin (LVM-thin, ZFS,
   Ceph) attiva **Discard**.
3. Facoltativo: togli la spunta **Backup** se non serve includere i log nei backup della VM.

### Nella VM

```bash
lsblk                                   # individua il nuovo disco, es. /dev/sdb (100G, senza partizioni)

sudo parted /dev/sdb --script mklabel gpt mkpart fwlog ext4 0% 100%
sudo mkfs.ext4 -L fwlog-data -m 0 /dev/sdb1   # -m 0: nessuno spazio riservato a root

sudo mkdir -p /srv/fwlog
sudo blkid -s UUID -o value /dev/sdb1   # copia l'UUID
```

Aggiungi a `/etc/fstab` (sostituisci l'UUID):

```
UUID=19c91afe-xxxx-xxxx-xxxx-xxxxxxxxxxxx  /srv/fwlog  ext4  defaults,noatime,nofail  0  2
```

`nofail` permette alla VM di avviarsi anche se il disco manca; in quel caso è
`RequiresMountsFor` nella unit a impedire l'avvio di fwlog.

```bash
sudo systemctl daemon-reload
sudo mount -a
findmnt /srv/fwlog                      # deve mostrare /dev/sdb1 con opzione noatime
```

### Se il disco è già formattato e montato

Si può adeguare senza riformattare:

```bash
sudo e2label /dev/sdb1 fwlog-data       # etichetta
sudo tune2fs -m 0 /dev/sdb1             # recupera il 5% riservato a root (~5 GB su 100 GB)
sudo mount -o remount /srv/fwlog        # applica noatime se è già in fstab
```

e in `/etc/fstab` usare `0 2` come ultime due colonne (il `1` è riservato al disco di sistema).

---

## 2. Installazione

Su Ubuntu 24.04 o successivo (testato su 26.04), con il disco dati già montato:

```bash
git clone https://github.com/MattiaC46/fwlog.git
cd fwlog
sudo ./install.sh
```

Il repository è privato: per clonarlo sulla VM serve un accesso GitHub (es. `gh auth login`
oppure un token), in alternativa copia la cartella con `scp`.

Lo script:

- installa `python3` e `openssl`, crea l'utente di sistema `fwlog`;
- copia il programma in `/opt/fwlog`;
- si ferma se `/srv/fwlog` non è un mount point (per forzare: `sudo FORCE=1 ./install.sh`);
- genera certificato autofirmato e `/etc/fwlog/fwlog.env` con una password casuale,
  **solo se non esistono già**;
- alza i buffer UDP del kernel (`/etc/sysctl.d/90-fwlog.conf`);
- installa e avvia il servizio `fwlog`.

Alla fine stampa l'indirizzo della dashboard e la password.

Se `ufw` è attivo, apri le porte (meglio limitandole alle reti dei firewall):

```bash
sudo ufw allow from 192.168.1.0/24 to any port 514 proto udp
sudo ufw allow from 192.168.1.0/24 to any port 514 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 8443 proto tcp
```

**Aggiornamento:** `git pull && sudo ./install.sh`. Configurazione, certificato e
database non vengono toccati.

---

## 3. Primo accesso

1. Apri `https://<IP-della-VM>:8443/`.
2. Il certificato è autofirmato: accetta l'avviso del browser.
3. Accedi con utente `admin` e la password stampata dall'installazione.

Password dimenticata: `sudo grep PASS /etc/fwlog/fwlog.env`.
Per cambiarla modifica il file e poi `sudo systemctl restart fwlog`.

I firewall compaiono da soli nella barra laterale al primo messaggio ricevuto.
Sono identificati dall'IP da cui arrivano i pacchetti; il nome iniziale è l'hostname
del messaggio syslog (o l'IP) e si cambia con **Rinomina**.

---

## 4. Configurazione dei firewall

Negli esempi il server fwlog è `192.168.200.56`. UDP è il più semplice; TCP non perde
messaggi se la rete è congestionata.

Per tutti i firewall vale la stessa regola: oltre a indicare il server syslog bisogna
**attivare il log sulle regole** che interessano, altrimenti il firewall non invia nulla.

### pfSense

1. **Status → System Logs → Settings**.
2. Spunta **Enable Remote Logging**, in **Remote log servers** scrivi `192.168.200.56:514`.
3. In **Remote Syslog Contents** spunta **Firewall Events**. Salva.
4. Nella stessa pagina, **Log packets matched from the default block rules** registra
   il traffico bloccato di default.
5. Per le regole di pass: **Firewall → Rules → modifica la regola → Log packets that are
   handled by this rule**.

### OPNsense

1. **System → Settings → Logging → Remote**, aggiungi una destinazione.
2. Transport **UDP(4)** o **TCP(4)**, Hostname `192.168.200.56`, Port `514`.
3. In **Applications** scegli **filter (filterlog)**, livelli da `info` in su. Salva e Applica.
4. Sulle regole: **Firewall → Rules → modifica → Log packets that are handled by this rule**.

### FortiGate

Da CLI:

```
config log syslogd setting
    set status enable
    set server "192.168.200.56"
    set mode udp            # "reliable" per TCP
    set port 514
    set format default
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
end
```

Log sulle policy (anche da GUI: policy → **Log Allowed Traffic → All Sessions**):

```
config firewall policy
    edit 3
        set logtraffic all
    next
end
```

Il traffico negato dalla policy implicita si registra con
`config log setting` → `set fwpolicy-implicit-log enable`.

### Sophos Firewall

1. **Configure → System services → Log settings → Add** (Syslog server).
2. IP `192.168.200.56`, porta `514`, facility a piacere, severity **Information**,
   formato **Standard format**.
3. Nella tabella sottostante spunta per il nuovo server almeno **Firewall → Firewall rules**
   (e se interessa **Invalid traffic**, **Local ACLs**, **DoS attack**).
4. Sulle regole firewall attiva **Log firewall traffic**.

### MikroTik (RouterOS)

```
/system logging action add name=fwlog target=remote remote=192.168.200.56 remote-port=514 bsd-syslog=yes
/system logging add topics=firewall action=fwlog
```

Attiva il log sulle regole, ad esempio tutte le drop della chain input:

```
/ip firewall filter set [find chain=input action=drop] log=yes log-prefix="DROP"
```

RouterOS non scrive l'azione nel messaggio: usa un `log-prefix` parlante (`DROP`,
`ACCEPT`) e cercalo con il filtro **Testo**.

### Palo Alto

1. **Device → Server Profiles → Syslog → Add**: server `192.168.200.56`, Transport
   UDP o TCP, Port `514`, **Format BSD**.
2. **Objects → Log Forwarding → Add**: aggiungi una voce per **Log Type traffic** (e
   **threat** se interessa) con il profilo syslog appena creato.
3. **Policies → Security**: su ogni regola, scheda **Actions**, scegli il profilo di
   **Log Forwarding** e lascia attivo **Log at Session End**.
4. **Commit**.

### Cisco ASA

```
logging enable
logging timestamp
logging device-id hostname
logging trap informational
logging host inside 192.168.200.56
! per TCP:  logging host inside 192.168.200.56 tcp/514
!           logging permit-hostdown
```

Con TCP aggiungi **sempre** `logging permit-hostdown`: senza, se fwlog non risponde
l'ASA blocca il nuovo traffico.

Per le ACL aggiungi `log` alle righe interessate, es.
`access-list outside_access_in extended deny ip any any log`.

### Linux con UFW (rsyslog)

Attiva il log di UFW (`sudo ufw logging low`) e crea `/etc/rsyslog.d/90-fwlog.conf`:

```
if $msg contains "[UFW " then {
    action(type="omfwd" target="192.168.200.56" port="514" protocol="tcp"
           TCP_Framing="octet-counted"
           queue.type="LinkedList" queue.size="10000" action.resumeRetryCount="-1")
}
```

Poi `sudo systemctl restart rsyslog`. La coda locale conserva i messaggi se fwlog è
temporaneamente irraggiungibile. Lo stesso schema funziona per iptables/nftables
(cambiando il testo cercato con il prefisso usato nelle regole).

---

## 5. Uso dei filtri

Scegli un firewall nella barra laterale, compila uno o più campi e premi **Invio**
o **Applica filtri**. I filtri si combinano tra loro (tutti devono essere veri).

| Campo | Esempio | Significato |
|---|---|---|
| IP | `192.168.1.10` | sorgente **o** destinazione |
| IP | `10.0.0.0/8` | qualsiasi indirizzo della subnet (anche IPv6, es. `2001:db8::/32`) |
| Sorgente | `!192.168.0.0/16` | sorgente **non** nella rete interna |
| Porta dst | `3389` | solo traffico verso RDP |
| Porta | `!443` | né sorgente né destinazione 443 (include i log senza porta) |
| Interfaccia | `wan1` | in ingresso **o** in uscita su `wan1` |
| Zona | `untrust` | zona sorgente o destinazione |
| Azione | `deny` | `allow` / `deny`, oppure il valore originale del vendor |
| Protocollo | `udp` | |
| Regola | `!0` | esclude la policy implicita (FortiGate) |
| Testo | `UFW BLOCK` | cerca nel messaggio completo |
| Da / A | | intervallo di tempo (ora di ricezione) |

- `!` davanti a qualsiasi valore lo **esclude**.
- I confronti di testo non distinguono maiuscole e minuscole.
- Nella tabella **clic** su un IP, porta, interfaccia, zona, regola, azione o protocollo
  aggiunge quel filtro; **Alt+clic** lo aggiunge come esclusione.
- **Clic sulla riga** mostra il messaggio originale completo.
- **Live** aggiorna la tabella ogni 4 secondi con i nuovi log, mantenendo i filtri.
- **Esporta CSV** scarica i log filtrati (fino a 100.000 righe).

Il filtro **Testo** legge tutti i messaggi: su archivi grandi è più veloce se combinato
con un intervallo di tempo o con un filtro IP.

---

## 6. Configurazione

Tutto in `/etc/fwlog/fwlog.env`; dopo una modifica: `sudo systemctl restart fwlog`.

| Variabile | Default | Descrizione |
|---|---|---|
| `FWLOG_DATA_DIR` | `/srv/fwlog` | cartella del database |
| `FWLOG_SYSLOG_BIND` | `0.0.0.0` | indirizzo di ascolto syslog (`::` per IPv4 + IPv6) |
| `FWLOG_SYSLOG_UDP` | `514` | porta UDP, `0` = disattivata |
| `FWLOG_SYSLOG_TCP` | `514` | porta TCP, `0` = disattivata |
| `FWLOG_WEB_BIND` | `0.0.0.0` | indirizzo della dashboard |
| `FWLOG_WEB_PORT` | `8443` | porta della dashboard |
| `FWLOG_WEB_USER` | `admin` | utente |
| `FWLOG_WEB_PASS` | generata | password; se vuota la dashboard **non** è protetta |
| `FWLOG_TLS_CERT`, `FWLOG_TLS_KEY` | `/etc/fwlog/tls.*` | certificato; se vuoti la dashboard è in HTTP |
| `FWLOG_RETENTION_DAYS` | `90` | conservazione predefinita in giorni, `0` = senza limite; ogni firewall può averne una propria dalla dashboard |
| `FWLOG_MIN_FREE_GB` | `2` | sotto questo spazio libero vengono eliminati i log più vecchi |
| `FWLOG_ALLOWED_SOURCES` | vuoto | IP/subnet ammessi, es. `192.168.1.1,10.0.0.0/24`; vuoto = tutti |
| `FWLOG_QUEUE_MAX` | `200000` | messaggi in attesa di scrittura; oltre vengono scartati |

Per usare un certificato proprio, sostituisci `/etc/fwlog/tls.crt` e `tls.key`
(proprietario `root:fwlog`, chiave in `0640`) e riavvia.

---

## 7. Spazio su disco

Ogni log occupa circa **400–600 byte** nel database, indici compresi (circa 470 byte
misurati con i campioni di prova). Un disco da 100 GB contiene quindi circa
180 milioni di log.

| Media msg/s | Log al giorno | Spazio al giorno | Giorni in ~90 GB |
|---:|---:|---:|---:|
| 5 | 430.000 | 0,2 GB | oltre 90 (limite di conservazione) |
| 20 | 1,7 milioni | 0,9 GB | circa 100 |
| 50 | 4,3 milioni | 2,2 GB | circa 40 |
| 100 | 8,6 milioni | 4,3 GB | circa 20 |

La media reale è visibile nella barra laterale (msg/min per firewall). Ogni minuto fwlog:

- elimina i log più vecchi della conservazione di ciascun firewall (pulsante
  **Conservazione** nella dashboard; se non impostata vale `FWLOG_RETENTION_DAYS`);
- se lo spazio libero scende sotto `FWLOG_MIN_FREE_GB`, elimina i log più vecchi finché
  non torna sopra soglia. Il disco quindi non si riempie mai, ma la conservazione
  effettiva può risultare più breve di quella impostata.

### Ampliare il disco

1. Proxmox: VM → **Hardware** → disco dati → **Disk Action → Resize**, aggiungi i GB.
2. Nella VM, a caldo e senza fermare fwlog:

```bash
echo 1 | sudo tee /sys/class/block/sdb/device/rescan   # rileva la nuova dimensione
sudo apt-get install -y cloud-guest-utils              # fornisce growpart (se manca)
sudo growpart /dev/sdb 1                               # allarga la partizione
sudo resize2fs /dev/sdb1                               # allarga il filesystem
df -h /srv/fwlog
```

---

## 8. Gestione

```bash
systemctl status fwlog          # stato
journalctl -u fwlog -f          # log del servizio
sudo systemctl restart fwlog    # riavvio (i messaggi in coda vengono salvati)
```

Il piè della barra laterale mostra spazio libero, dimensione del database e **messaggi
scartati**. Se gli scartati crescono, il server non riesce a scrivere abbastanza in
fretta: verifica la velocità del disco o riduci i log inviati (es. solo traffico negato).

Pulsanti nell'intestazione di un firewall:

- **Conservazione**: per quanti giorni tenere i log di quel firewall (predefinita,
  un valore a scelta o illimitata). I log oltre il limite spariscono entro un minuto.
- **Elimina log**: cancella i log più vecchi di N giorni, solo quelli che corrispondono
  ai filtri applicati (es. `Azione = deny` e `Porta dst = 53`), oppure tutti. Prima di
  confermare mostra quanti log verranno eliminati; i log che arrivano nel frattempo non
  vengono toccati. Le eliminazioni grandi procedono a blocchi senza fermare la ricezione.
- **Elimina firewall**: cancella il firewall e tutti i suoi log. Se il firewall
  continua a inviare, ricompare automaticamente (vuoto).

Lo spazio liberato viene riutilizzato dal database; il file si riduce gradualmente.

---

## 9. Test con test-sender.py

`test-sender.py` invia un esempio di log per ogni formato supportato:

```bash
python3 test-sender.py 192.168.200.56            # UDP
python3 test-sender.py 192.168.200.56 --tcp      # TCP
python3 test-sender.py 192.168.200.56 -n 50000   # prova di carico
```

Dopo l'invio compare un firewall con l'IP della macchina da cui hai lanciato lo script;
puoi eliminarlo dalla dashboard a fine prova. Nella prova di carico **Messaggi scartati**
deve restare 0.

Prova locale senza installare (porte non privilegiate, HTTP, senza password):

```bash
mkdir -p /tmp/fwlog
FWLOG_DATA_DIR=/tmp/fwlog FWLOG_SYSLOG_UDP=5514 FWLOG_SYSLOG_TCP=5514 \
FWLOG_WEB_PORT=8080 FWLOG_MIN_FREE_GB=0.5 python3 fwlog.py
# in un altro terminale
python3 test-sender.py 127.0.0.1 -p 5514
# poi apri http://localhost:8080/
```

---

## 10. Limiti noti

- **Ora di ricezione**, non quella del firewall: gli orologi e i formati data dei
  dispositivi sono troppo inaffidabili. Un ritardo di rete o di coda sposta di poco l'ora.
- I firewall sono identificati dall'**IP sorgente** dei pacchetti: due firewall dietro lo
  stesso NAT risultano uno solo; un firewall che cambia IP compare come nuovo.
- Niente syslog su TLS (porta 6514).
- Un solo utente per la dashboard.
- MikroTik non indica l'azione nel messaggio (vedi `log-prefix`); Cisco ASA registra sia
  apertura sia chiusura delle connessioni (`Built`/`Teardown`), entrambe come `allow`.
- Pensato per piccole e medie aziende, fino a qualche migliaio di messaggi al secondo.
  Oltre conviene una soluzione come Graylog o basata su ClickHouse.
