# Installazione pulita su Rocky Linux 9

Guida passo passo per installare fwlog su una VM **Rocky Linux 9** in Proxmox, partendo
da zero, con la dashboard su una **porta diversa dalla 8443**.

Negli esempi la porta della dashboard è **9443**: sostituiscila con quella che preferisci
(qualsiasi porta libera tra 1 e 65535, tranne 514).

> La guida generale (configurazione dei firewall, filtri, variabili) resta il
> [README](../README.md). Qui ci sono solo le differenze e i passaggi per Rocky 9.

---

## 0. Riepilogo

| Cosa              | Valore                                   |
|-------------------|------------------------------------------|
| Sistema           | Rocky Linux 9 (minimal va bene)          |
| Disco di sistema  | anche piccolo (15 GB), non riceve log    |
| Disco dati        | secondo disco ext4 montato su `/srv/fwlog` |
| Syslog            | UDP 514 e TCP 514                        |
| Dashboard         | `https://<IP-VM>:9443/`                  |
| Python            | `python3` di sistema (3.9), nessun pacchetto aggiuntivo |

---

## 1. Creazione della VM in Proxmox

1. Crea la VM con l'ISO di Rocky Linux 9 (installazione *Minimal* sufficiente).
2. Disco di sistema: 15–20 GB.
3. **Hardware → Add → Hard Disk**: secondo disco per i log (dimensione in base ai volumi,
   circa 400–600 byte per log; 50 GB ≈ 100 milioni di log).
   Bus SCSI con *VirtIO SCSI single*, *Discard* attivo se lo storage è thin.
4. Rete con IP statico (i firewall devono sapere dove inviare i log).
5. Avvia l'installazione di Rocky e, nella schermata dei dischi, **seleziona solo il
   disco di sistema**: il secondo disco va lasciato vuoto.

Dopo il primo avvio aggiorna il sistema:

```bash
sudo dnf -y update
sudo reboot
```

---

## 2. Preparazione del disco dati

> **Attenzione:** `mkfs` cancella il disco. Verifica due volte il nome del dispositivo.

```bash
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
```

Il disco dati è quello senza partizioni né mount point (di solito `/dev/sdb`).

```bash
DISK=/dev/sdb                      # <-- verifica!
sudo mkfs.ext4 -L fwlog-data -m 0 "$DISK"
sudo mkdir -p /srv/fwlog
UUID=$(sudo blkid -s UUID -o value "$DISK")
echo "UUID=$UUID  /srv/fwlog  ext4  defaults,noatime,nofail  0  2" | sudo tee -a /etc/fstab
sudo systemctl daemon-reload
sudo mount -a
sudo restorecon -Rv /srv/fwlog     # etichette SELinux corrette sul nuovo filesystem
findmnt /srv/fwlog                 # deve mostrare il disco
```

---

## 3. Prerequisiti

`git` per scaricare il repository (python3 e openssl li installa lo script):

```bash
sudo dnf -y install git
```

Controlla che nessun altro servizio usi la porta 514 (rsyslog su Rocky di default **non**
ascolta in rete, ma meglio verificare) né la porta scelta per la dashboard:

```bash
sudo ss -ulpn | grep ':514 '
sudo ss -tlpn | grep -E ':(514|9443) '
```

Non deve uscire nulla. Se rsyslog risultasse in ascolto su 514, commenta in
`/etc/rsyslog.conf` le righe `module(load="imudp")`/`input(type="imudp" ...)` (e le
equivalenti `imtcp`) e poi `sudo systemctl restart rsyslog`.

---

## 4. Installazione

Il repository è privato: per clonarlo serve un accesso GitHub (`gh auth login`, un token
o una deploy key). In alternativa copia la cartella con `scp`.

```bash
git clone https://github.com/MattiaC46/fwlog.git
cd fwlog
sudo WEB_PORT=9443 ./install.sh
```

`WEB_PORT` va passata **dopo** `sudo` (sudo non conserva le variabili d'ambiente).

Lo script:

- installa `python3` e `openssl` con `dnf`, crea l'utente di sistema `fwlog`;
- copia il programma in `/opt/fwlog`;
- si ferma se `/srv/fwlog` non è un mount point;
- genera certificato autofirmato e `/etc/fwlog/fwlog.env` con password casuale e
  `FWLOG_WEB_PORT=9443`;
- alza i buffer UDP del kernel;
- installa e avvia il servizio `fwlog`.

Alla fine stampa URL e **password**: annotala.

> `WEB_PORT` vale solo alla prima installazione, quando `/etc/fwlog/fwlog.env` non
> esiste. Se il file c'è già, lo script avvisa e non lo modifica (vedi § 9).

---

## 5. Firewall della VM (firewalld)

Su Rocky firewalld è attivo di default e blocca tutto: le porte vanno aperte.

**Semplice** (da qualsiasi rete):

```bash
sudo firewall-cmd --permanent --add-port=514/udp --add-port=514/tcp --add-port=9443/tcp
sudo firewall-cmd --reload
```

**Consigliato**: syslog solo dalle reti dei firewall, dashboard solo dalla rete di
gestione. Esempio con firewall in `192.168.1.0/24` e amministratori in `10.0.0.0/24`:

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="514" protocol="udp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="514" protocol="tcp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/24" port port="9443" protocol="tcp" accept'
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

Per una protezione in più a livello applicativo imposta anche `FWLOG_ALLOWED_SOURCES`
in `/etc/fwlog/fwlog.env` (es. `192.168.1.1,192.168.1.254`).

---

## 6. SELinux

Lascialo in modalità **enforcing**: non serve nessuna modifica. Il servizio parte da
systemd come `/usr/bin/python3` e gira nel dominio `unconfined_service_t`, quindi può
usare la porta 514 (grazie a `CAP_NET_BIND_SERVICE` della unit) e qualsiasi porta per
la dashboard senza `semanage port`.

Verifica:

```bash
getenforce                              # Enforcing
ps -eZ | grep -i python3                # ... unconfined_service_t ... python3
sudo ausearch -m AVC -ts recent         # nessun rifiuto relativo a fwlog
```

---

## 7. Verifica

```bash
systemctl status fwlog
sudo ss -ulpn | grep ':514 '            # python3 in ascolto UDP
sudo ss -tlpn | grep -E ':(514|9443) '  # python3 in ascolto TCP
journalctl -u fwlog -n 30 --no-pager
```

Invio di log di prova dalla VM stessa:

```bash
python3 /opt/fwlog/test-sender.py 127.0.0.1
python3 /opt/fwlog/test-sender.py 127.0.0.1 --tcp
```

Poi apri `https://<IP-della-VM>:9443/`, accetta l'avviso del certificato autofirmato
e accedi con `admin` e la password stampata. Deve comparire il firewall `127.0.0.1`
con i log di esempio (si può eliminare dalla dashboard con **Elimina firewall**).

Password dimenticata: `sudo grep PASS /etc/fwlog/fwlog.env`.

---

## 8. Configurazione dei firewall

Imposta come server syslog l'IP della VM, porta 514 UDP (o TCP). Le istruzioni per
pfSense, OPNsense, FortiGate, Sophos, MikroTik, Palo Alto, Cisco ASA e Linux sono
nel [README](../README.md).

---

## 9. Cambiare la porta in un secondo momento

```bash
sudo sed -i 's/^FWLOG_WEB_PORT=.*/FWLOG_WEB_PORT=10443/' /etc/fwlog/fwlog.env
sudo systemctl restart fwlog
sudo firewall-cmd --permanent --remove-port=9443/tcp --add-port=10443/tcp   # o aggiorna le rich rule
sudo firewall-cmd --reload
```

---

## 10. Aggiornamento e manutenzione

```bash
cd fwlog && git pull && sudo ./install.sh
```

Configurazione, certificato, porta e database non vengono toccati.

**Ampliare il disco dati:** aumenta il disco in Proxmox (*Disk Action → Resize*), poi
sulla VM, a caldo:

```bash
echo 1 | sudo tee /sys/class/block/sdb/device/rescan
sudo resize2fs /dev/sdb
df -h /srv/fwlog
```

---

## 11. Problemi comuni

| Sintomo | Causa / soluzione |
|---------|-------------------|
| `install.sh` si ferma: `/srv/fwlog non e' un mount point` | Il disco dati non è montato: ripeti il § 2 (`findmnt /srv/fwlog`). |
| Il servizio non parte dopo un riavvio | Disco dati non montato (`nofail` lascia partire il sistema ma fwlog no, apposta): `sudo mount -a`, poi `sudo systemctl start fwlog`. |
| Dashboard irraggiungibile, `curl -k https://localhost:9443/` funziona | firewalld: controlla `sudo firewall-cmd --list-all` (§ 5). |
| Nessun log dai firewall | `sudo tcpdump -ni any port 514` per vedere se arrivano; poi firewalld e `FWLOG_ALLOWED_SOURCES`. |
| `Address already in use` nel journal | Un altro servizio usa 514 o la porta della dashboard (§ 3). |
| Rifiuti SELinux in `ausearch` | Riapplica le etichette: `sudo restorecon -Rv /srv/fwlog /opt/fwlog /etc/fwlog`. |
