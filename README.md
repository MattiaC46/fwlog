# fwlog

Server syslog semplice dedicato ai **log dei firewall** e agli **accessi degli
amministratori dei server Windows**, con dashboard web.

I firewall inviano syslog (UDP o TCP 514). fwlog estrae sorgente, destinazione, porte,
protocollo, azione, interfacce, zone e regola, e li salva in SQLite su un disco dedicato.
Dalla dashboard si sceglie un firewall e si filtrano i suoi log.

I server Windows (2016–2025, anche controller di dominio) inviano via HTTPS gli accessi
degli account amministratori, riusciti e falliti, letti dal registro Security da uno script
PowerShell pianificato: nessun programma da installare (vedi [sezione 5](#5-accessi-degli-amministratori-server-windows)).

- Un solo file Python, sola libreria standard: niente `pip`, niente dipendenze.
- Formati riconosciuti: pfSense, OPNsense, FortiGate, Sophos Firewall, Palo Alto,
  Cisco ASA/FTD, MikroTik, SonicWall, Zyxel, iptables/UFW, UniFi e in generale i log
  `chiave=valore`. Gli altri messaggi vengono comunque salvati e sono cercabili per testo.
- Conservazione automatica (90 giorni di default, modificabile per ogni firewall),
  eliminazione dei log dalla dashboard e protezione del disco pieno.
- **Registro accessi amministratori** separato (server Windows e login ai firewall), con
  conservazione propria, per il provvedimento del Garante sugli amministratori di sistema.
- **Backup pianificati** dalla dashboard su disco o NAS montato, S3 (AWS, Wasabi, Backblaze,
  MinIO...) o condivisione SMB, con cifratura, e **ripristino** anche su una macchina nuova.

Non è un SIEM: niente correlazione, alert o gestione utenti.

> **Rocky Linux 9 / RHEL 9:** guida dedicata in [docs/INSTALL-ROCKY9.md](docs/INSTALL-ROCKY9.md)
> (dnf, firewalld, SELinux, porta della dashboard personalizzata).

---

## Indice

1. [Preparazione del secondo disco](#1-preparazione-del-secondo-disco)
2. [Installazione](#2-installazione)
3. [Primo accesso](#3-primo-accesso)
4. [Configurazione dei firewall](#4-configurazione-dei-firewall)
5. [Accessi degli amministratori (server Windows)](#5-accessi-degli-amministratori-server-windows)
6. [Registro accessi amministratori](#6-registro-accessi-amministratori)
7. [Uso dei filtri](#7-uso-dei-filtri)
8. [Configurazione](#8-configurazione)
9. [Spazio su disco](#9-spazio-su-disco)
10. [Gestione](#10-gestione)
11. [Backup e ripristino](#11-backup-e-ripristino)
12. [Test con test-sender.py](#12-test-con-test-senderpy)
13. [Limiti noti](#13-limiti-noti)

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

La dashboard è sulla porta **10443**. Per usarne un'altra: `sudo WEB_PORT=11443 ./install.sh`
(vale solo alla prima installazione; la variabile va scritta dopo `sudo`). Su Rocky Linux 9 segui
[docs/INSTALL-ROCKY9.md](docs/INSTALL-ROCKY9.md).

Se conosci già gli IP dei firewall e degli switch, indicali subito: solo loro potranno
inviare syslog, e lo script stampa i comandi del firewall della VM già limitati a quelle
sorgenti:

```bash
sudo ALLOWED_SOURCES=192.168.1.1,192.168.1.254,10.0.10.0/24 ./install.sh
```

Si possono impostare anche dopo, con `FWLOG_ALLOWED_SOURCES` (sezione 8).

Il repository è pubblico: `git clone` funziona senza account GitHub né credenziali.
Per installare una versione precisa: `git clone --branch <tag> https://github.com/MattiaC46/fwlog.git`.

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
sudo ufw allow from 192.168.1.0/24 to any port 10443 proto tcp
```

**Aggiornamento:** `git pull && sudo ./install.sh`. Configurazione, certificato e
database non vengono toccati.

**VM template da clonare per più clienti:** prima della copia esegui
`sudo ./prepara-template.sh`, poi da ogni cliente monta il disco dati ed esegui
`sudo ./install.sh` (password e certificato nuovi). Procedura in
[docs/INSTALL-ROCKY9.md § 12](docs/INSTALL-ROCKY9.md#12-vm-template-da-distribuire-ai-clienti).

---

## 3. Primo accesso

1. Apri `https://<IP-della-VM>:10443/`.
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

## 5. Accessi degli amministratori (server Windows)

fwlog registra gli accessi degli **account amministratori** ai server Windows
(Windows Server 2016–2025, controller di dominio compresi). Sul server non si installa
nessun programma: `fwlog-agent.ps1` è uno script PowerShell che gira **ogni minuto come
attività pianificata** (utente SYSTEM), legge dal registro Security solo gli eventi nuovi,
tiene quelli che riguardano amministratori e li invia a fwlog via HTTPS. Non resta nessun
processo attivo tra un giro e l'altro.

### Cosa viene registrato

| Evento | Event ID |
|---|---|
| Accesso (locale, RDP, rete, sblocco, credenziali in cache) | 4624 |
| Accesso fallito, con il motivo (password errata, utente inesistente, account bloccato…) | 4625; sui DC anche 4771 (Kerberos) e 4776 (NTLM) |
| Disconnessione, RDP scollegato o riconnesso | 4634, 4647, 4779, 4778 |
| Uso di credenziali esplicite (runas, accesso ad altri server) | 4648 |
| Account bloccato, sbloccato, password cambiata o reimpostata, account abilitato, disabilitato, eliminato | 4740, 4767, 4723, 4724, 4722, 4725, 4726 |
| Aggiunta o rimozione da un gruppo privilegiato (Administrators, Domain Admins, Enterprise Admins, Remote Desktop Users, operatori…) | 4728/4729, 4732/4733, 4756/4757 |
| **Registro di controllo cancellato**, **criteri di controllo modificati** | 1102, 4719 |

Gli eventi critici (registro cancellato, criteri modificati, aggiunte a gruppi
privilegiati) sono evidenziati in ambra; la barra laterale mostra per ogni server gli
eventi critici e gli accessi falliti delle ultime 24 ore.

**Solo amministratori.** L'agente considera amministratori:

- i membri, anche indiretti, del gruppo Administrators locale e, in un dominio, del gruppo
  Administrators del dominio e dei gruppi di dominio presenti nel gruppo locale;
- gli account protetti di Active Directory (`adminCount=1`: Domain Admins, Enterprise
  Admins, operatori…);
- gli account che ricevono privilegi speciali all'accesso (evento 4672);
- i nomi tipici `administrator`, `admin`, `amministratore` anche se l'account non esiste,
  per vedere i tentativi di attacco;
- gli account indicati con `-ExtraAdmin`.

Sono esclusi account computer, SYSTEM e servizi di sistema, attività pianificate e
servizi (accessi di tipo 4 e 5) e gli account indicati con `-ExcludeUser` (utile per gli
account di servizio del backup o di SQL Server, che accedono di continuo). Gli accessi di
rete ripetuti (tipo 3, frequenti sui controller di dominio) dello stesso utente dallo
stesso IP vengono registrati al massimo uno ogni 10 minuti.

L'ora mostrata è quella dell'evento sul server Windows (sincronizzato dal dominio), non
quella di ricezione: gli eventi inviati in ritardo finiscono al posto giusto.

### Aggiungere un server

1. Nella dashboard: **Server Windows → Aggiungi**, scegli un nome (es. `DC01`).
2. Scarica `fwlog-agent.ps1` dal link nella finestra e copialo sul server.
3. Controlla l'indirizzo di fwlog proposto: deve essere raggiungibile **dal server**
   (porta TCP 10443).
4. Sul server, in PowerShell **come amministratore**, nella cartella del file, esegui il
   comando mostrato (pulsante **Copia comando**), ad esempio:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\fwlog-agent.ps1 -Install -Url https://192.168.1.20:10443 -Token 3f1c… -Pin 9A0B…
   ```

   Opzioni: `-ExcludeUser svc_backup,svc_sql` e `-ExtraAdmin mario.rossi`.
5. Entro un minuto il server diventa verde nella barra laterale.

Il token è personale per ogni server e si vede **solo alla creazione**: fwlog ne conserva
solo l'impronta. Se lo perdi, o se il server viene dismesso, usa **Nuovo token**
(il vecchio smette subito di funzionare) e riesegui il comando sul server.
`-Pin` è l'impronta SHA-256 del certificato di fwlog: l'agente rifiuta qualsiasi altro
certificato, quindi il token non può essere intercettato da un falso server. Se sostituisci
il certificato di fwlog, riesegui l'installazione sui server con la nuova impronta.

Se il firewall della VM è attivo, apri la porta della dashboard ai server, ad esempio:

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 port port=10443 protocol=tcp accept'
sudo firewall-cmd --reload
```

### Cosa fa l'installazione sul server

- copia lo script in `C:\Program Files\fwlog` (modificabile solo dagli amministratori);
- salva configurazione e stato in `C:\ProgramData\fwlog`, leggibile solo da SYSTEM e
  Administrators perché contiene il token; il registro dell'agente è
  `C:\ProgramData\fwlog\agent.log`;
- attiva con `auditpol` i criteri di controllo necessari (Logon, Logoff, Special Logon,
  Account Lockout, Other Logon/Logoff Events, User Account Management, Security Group
  Management, Audit Policy Change; sui DC anche Credential Validation e Kerberos
  Authentication Service) e fa prevalere le sottocategorie sulle categorie legacy;
- porta il registro Security ad almeno 256 MB;
- invia subito una prova (con gli eventi delle ultime 24 ore) e crea l'attività pianificata
  `\fwlog\fwlog-agent`, eseguita ogni minuto come SYSTEM.

**Domini con GPO.** Se una GPO imposta i *criteri di controllo avanzati*, al primo
aggiornamento sovrascrive quelli locali. In quel caso configurali nella GPO (per i
controller di dominio nella *Default Domain Controllers Policy*): *Configurazione
computer → Criteri → Impostazioni di Windows → Impostazioni sicurezza → Configurazione
criteri di controllo avanzati*, con le sottocategorie elencate sopra (successo; per
Logon anche errore; sui DC errore per Credential Validation e Kerberos Authentication
Service). La dashboard avvisa se qualche criterio non è attivo.

Comandi utili sul server (PowerShell come amministratore):

```powershell
$a = "$env:ProgramFiles\fwlog\fwlog-agent.ps1"
powershell -ExecutionPolicy Bypass -File $a -Test        # un giro di prova con il dettaglio
Get-Content "$env:ProgramData\fwlog\agent.log" -Tail 20  # ultime righe del registro dell'agente
Get-ScheduledTask -TaskPath \fwlog\                      # stato dell'attività pianificata
powershell -ExecutionPolicy Bypass -File $a -Uninstall   # rimozione
```

### Affidabilità

- L'agente avanza solo quando fwlog conferma il salvataggio. Se fwlog è spento o
  irraggiungibile, gli eventi restano nel registro Security e vengono inviati appena torna
  disponibile; gli invii ripetuti non creano doppioni.
- Con 256 MB di registro Security si coprono da qualche giorno (controller di dominio
  molto attivi) a qualche settimana di interruzione. Se il registro viene sovrascritto
  prima della lettura, la dashboard lo segnala.
- Il pallino del server è verde se l'agente ha contattato fwlog negli ultimi 3 minuti,
  ambra fino a 15, **rosso** oltre: server spento, rete interrotta o agente disattivato.

### Conservazione e Garante privacy

Gli accessi riusciti degli amministratori seguono la conservazione del **registro accessi**
(sezione 6, 365 giorni di default); tutti gli altri eventi dei server quella del server
(`FWLOG_WIN_RETENTION_DAYS`, 365 giorni, modificabile per ogni server con
**Conservazione**: si può ridurre senza toccare il registro). Il provvedimento del Garante sugli
amministratori di sistema (27/11/2008) chiede di registrare gli accessi degli
amministratori e di conservarli per almeno **6 mesi**, in modo completo e inalterabile.
fwlog li tiene su una macchina separata, con credenziali diverse da quelle degli
amministratori Windows, ma **non** firma né cifra i registri: per una conformità formale
valuta con il tuo consulente se servono misure aggiuntive (ad esempio esportazioni CSV
periodiche su un archivio non modificabile).

Se il disco si riempie, vengono eliminati prima i log dei firewall e solo dopo, quando
non ce ne sono più, gli accessi dei server.

---

## 6. Registro accessi amministratori

**Accessi amministratori**, in cima alla barra laterale, raccoglie in un'unica tabella
solo gli **accessi riusciti con privilegi di amministratore**:

- dai **server Windows**: gli eventi «Accesso» con l'etichetta *admin* (token elevato);
- dai **firewall**: i login riusciti degli amministratori (GUI web, SSH, console, Winbox),
  riconosciuti nei syslog e copiati nel registro.

Tutto il resto (disconnessioni, accessi falliti, modifiche ai gruppi, login falliti ai
firewall...) resta nella pagina del server o nei log del firewall, con la loro
conservazione.

| Firewall | Cosa viene riconosciuto |
|---|---|
| pfSense, OPNsense | login alla GUI (`Successful login`, audit OPNsense `authenticated successfully`); SSH |
| FortiGate | eventi di sistema `Admin login successful` (GUI, SSH, console) |
| Sophos Firewall | eventi `Admin`/`GUI`/`CLI`/`SSH` di login riuscito |
| SonicWall | `Administrator login allowed` |
| MikroTik | `user ... logged in ... via winbox/ssh/web` (topic `system,account`, attivo di default) |
| Cisco ASA/FTD | `%ASA-6-605005` (login permesso) |
| Palo Alto | log SYSTEM `User ... logged in via ...` (inoltrare i log SYSTEM al server syslog) |
| Linux / UniFi / altri | OpenSSH: `Accepted password/publickey ...` |

Il firewall deve inviare anche i suoi **eventi di sistema**, non solo il traffico: su
FortiGate gli eventi di sistema (`config log eventfilter` → `set system enable`, attivo di
default) con severità almeno `information` nel filtro syslog; su pfSense e OPNsense i log
di sistema e di autenticazione oltre a quelli del firewall; su Palo Alto il log forwarding
dei log *System*.

Il registro ha una **conservazione propria** (pulsante **Conservazione**, predefinita
`FWLOG_ADMIN_RETENTION_DAYS`, 365 giorni), che vale sia per gli accessi ai server sia per i
login ai firewall. La **Conservazione** di ogni server e quella dei firewall valgono per
tutti gli altri eventi e log: si possono tenere log e altri eventi 30–90 giorni e gli
accessi admin un anno. **Elimina log** ed **Elimina firewall** non toccano il registro.
Con il disco pieno il registro viene eliminato per ultimo.

Filtri per dispositivo, utente, IP di origine (CIDR, `!` per escludere), testo e periodo; **Esporta CSV** produce l'estratto da consegnare in caso di verifica.
Dalla pagina di un firewall, **Accessi admin** apre il registro già filtrato.

I formati dei login sono stati scritti dalla documentazione dei produttori: se un login
non compare nel registro, cerca il messaggio nei log del firewall e segnalalo.

---

## 7. Uso dei filtri

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

## 8. Configurazione

Tutto in `/etc/fwlog/fwlog.env`; dopo una modifica: `sudo systemctl restart fwlog`.

| Variabile | Default | Descrizione |
|---|---|---|
| `FWLOG_DATA_DIR` | `/srv/fwlog` | cartella del database |
| `FWLOG_SYSLOG_BIND` | `0.0.0.0` | indirizzo di ascolto syslog (`::` per IPv4 + IPv6) |
| `FWLOG_SYSLOG_UDP` | `514` | porta UDP, `0` = disattivata |
| `FWLOG_SYSLOG_TCP` | `514` | porta TCP, `0` = disattivata |
| `FWLOG_WEB_BIND` | `0.0.0.0` | indirizzo della dashboard |
| `FWLOG_WEB_PORT` | `10443` | porta della dashboard |
| `FWLOG_WEB_USER` | `admin` | utente |
| `FWLOG_WEB_PASS` | generata | password; se vuota la dashboard **non** è protetta |
| `FWLOG_TLS_CERT`, `FWLOG_TLS_KEY` | `/etc/fwlog/tls.*` | certificato; se vuoti la dashboard è in HTTP |
| `FWLOG_RETENTION_DAYS` | `90` | conservazione predefinita in giorni, `0` = senza limite; ogni firewall può averne una propria dalla dashboard |
| `FWLOG_WIN_RETENTION_DAYS` | `365` | conservazione predefinita degli accessi dei server Windows, `0` = senza limite; modificabile per ogni server |
| `FWLOG_ADMIN_RETENTION_DAYS` | come `FWLOG_WIN_RETENTION_DAYS` | conservazione predefinita del registro accessi amministratori (accessi admin ai server e login ai firewall); modificabile dalla dashboard |
| `FWLOG_MIN_FREE_GB` | `2` | sotto questo spazio libero vengono eliminati i log più vecchi |
| `FWLOG_ALLOWED_SOURCES` | vuoto | IP/subnet ammessi a inviare syslog (firewall, switch), es. `192.168.1.1,10.0.0.0/24`; vuoto = tutti. Le voci non valide vengono ignorate e segnalate nel journal e nella dashboard |
| `FWLOG_QUEUE_MAX` | `200000` | messaggi in attesa di scrittura; oltre vengono scartati |

Per usare un certificato proprio, sostituisci `/etc/fwlog/tls.crt` e `tls.key`
(proprietario `root:fwlog`, chiave in `0640`) e riavvia.

---

## 9. Spazio su disco

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

## 10. Gestione

```bash
systemctl status fwlog          # stato
journalctl -u fwlog -f          # log del servizio
sudo systemctl restart fwlog    # riavvio (i messaggi in coda vengono salvati)
```

Il piè della barra laterale mostra spazio libero, dimensione del database e **messaggi
scartati**. Se gli scartati crescono, il server non riesce a scrivere abbastanza in
fretta: verifica la velocità del disco o riduci i log inviati (es. solo traffico negato).

Mostra anche lo stato delle **sorgenti syslog**:

- **Sorgenti syslog: tutte ammesse**: `FWLOG_ALLOWED_SOURCES` è vuoto e chiunque
  raggiunga la porta 514 può inviare log (e creare firewall nell'elenco). Indica firewall
  e switch nella variabile e riavvia.
- **Voci ignorate**: valori della variabile che non sono IP o subnet validi (es.
  `192.168.1.300`); vanno corretti, perché quel dispositivo viene rifiutato.
- **Da sorgenti non ammesse**: messaggi e connessioni rifiutati, con gli ultimi IP,
  quante volte e quando. Se compare un tuo dispositivo, aggiungilo alla variabile.

Le connessioni TCP da sorgenti non ammesse vengono chiuse subito e non occupano posti
tra le 500 connessioni contemporanee. Per una protezione anche a livello di rete limita
la porta 514 alle stesse sorgenti nel firewall della VM (vedi
[docs/INSTALL-ROCKY9.md](docs/INSTALL-ROCKY9.md)).

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

## 11. Backup e ripristino

Pagina **Backup** nella barra laterale. Tutto si configura da qui: dove salvare
(destinazioni), cosa e quando (job), il ripristino.

### Destinazioni

| Tipo | Uso |
|---|---|
| **Cartella** | disco USB o aggiuntivo, oppure NAS montato sulla VM (NFS o SMB in `/etc/fstab`), sotto `/mnt` o `/media` |
| **S3** | AWS S3, Wasabi, Backblaze B2, MinIO, NAS con server S3 (Synology, QNAP). Endpoint, regione, bucket, cartella, chiavi; path-style per MinIO e NAS |
| **SMB** | condivisione Windows o NAS, senza montarla (usa `smbclient`, installato da `install.sh`) |

**Prova** scrive e cancella un piccolo file. Una cartella viene rifiutata se è sul disco
di sistema o sul disco dei log: succede quando il NAS o il disco **non è montato**, così i
backup non riempiono il disco da 15 GB.

Esempio di NAS montato via NFS (come root):

```bash
mkdir -p /mnt/backup-fwlog
echo "nas.local:/volume1/backup  /mnt/backup-fwlog  nfs  defaults,_netdev,nofail  0 0" >> /etc/fstab
mount -a
mkdir -p /mnt/backup-fwlog/fwlog && chown fwlog:fwlog /mnt/backup-fwlog/fwlog
systemctl restart fwlog     # dopo aver montato un disco nuovo
```

Via SMB con mount: `//nas/backup /mnt/backup-fwlog cifs credentials=/root/.smb-nas,uid=fwlog,gid=fwlog,_netdev,nofail 0 0`
(in `/root/.smb-nas`: `username=...` e `password=...`, permessi `0600`; serve il pacchetto
`cifs-utils`). In alternativa la destinazione SMB non richiede alcun mount.

Per S3 conviene un utente (chiave) con permessi limitati al bucket: `s3:PutObject`,
`s3:GetObject`, `s3:ListBucket`, `s3:DeleteObject` (quest'ultimo serve per eliminare le
copie vecchie). Con il **versioning** o l'**Object Lock** del bucket i backup restano
anche se qualcuno li cancella: è il modo più semplice per avere copie non modificabili.

### Job

Ogni job sceglie:

- **cosa**: *Accessi amministratori* (solo il registro, pochi MB), *Log dei server* (tutti
  gli eventi dei server Windows) e/o *Log dei firewall* (anche molti GB). La configurazione (destinazioni, job, impostazioni, certificato TLS e
  `fwlog.env`) è sempre inclusa;
- **dove**: una destinazione;
- **quando**: ogni giorno, alcuni giorni della settimana, un giorno del mese, ogni N ore
  (dall'ora scelta) o solo a mano con **Esegui ora**. Un backup saltato a macchina spenta
  parte al riavvio;
- **quante copie** tenere: dopo ogni backup riuscito le più vecchie di quel job vengono
  eliminate dalla destinazione (`0` = mai);
- **cifratura** facoltativa (AES-256): consigliata fuori dalla rete aziendale, perché il
  registro contiene nomi utente e indirizzi IP. **Senza la password il backup non si
  può ripristinare.**

Configurazione consigliata: un job giornaliero con i soli accessi amministratori (cifrato,
su S3 o NAS, 30–60 copie) e, se servono, un job settimanale con i log dei firewall.
Ogni backup del registro contiene tutta la sua storia, quindi anche una sola copia copre
l'intera conservazione.

Si esegue un'operazione alla volta. Durante la copia la ricezione dei log continua; il
backup ha bisogno di spazio temporaneo su `/srv/fwlog` (circa quanto i dati salvati) e
si interrompe da solo se lo spazio libero scende vicino a `FWLOG_MIN_FREE_GB`, per non
far eliminare log dalla protezione del disco.

**Esporta configurazione** scarica destinazioni e job in un file JSON (con o senza
password e chiavi); **Importa configurazione** li ricrea su un'altra installazione.
Conserva questo file e le password di cifratura **fuori** da fwlog.

### Formato dei file

`fwlog-<macchina>-<job>-<data>-<ora>.fwbk` è un database SQLite compresso con gzip (e, se
cifrato, con `openssl enc -aes-256-cbc -pbkdf2`); accanto c'è un `.json` con il
riepilogo (contenuto, numero di righe, periodo, impronta SHA-256). Si può leggere anche
senza fwlog:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -in FILE.fwbk | gunzip > backup.db
# non cifrato:  gunzip -c FILE.fwbk > backup.db
sqlite3 backup.db "SELECT * FROM fw_admin LIMIT 10"
```

### Ripristino dalla dashboard

**Ripristina…**: scegli un backup da una destinazione (oppure carica un file `.fwbk`),
inserisci la password se è cifrato, poi cosa ripristinare:

- **Accessi amministratori**: solo il registro (gli altri eventi dei server non si
  toccano); **Log dei server**: tutti gli eventi e i server. Per entrambi: *aggiungi i dati
  mancanti* (non elimina nulla, utile per recuperare accessi persi) oppure *torna
  esattamente al backup* (quanto registrato dopo viene eliminato). I token degli agenti
  Windows restano validi;
- **Log dei firewall**: tutti i log attuali vengono sostituiti da quelli del backup.
  Intanto i log in arrivo restano in coda e vengono salvati alla fine;
- **Configurazione dei backup**: destinazioni e job aggiunti o aggiornati per nome.

I dati più vecchi della conservazione impostata vengono eliminati entro un minuto: per
consultare log vecchi, aumenta prima la conservazione.

### Consultare un backup senza ripristinarlo

**Consulta un backup…** (oppure *Consulta senza ripristinare* nella finestra di
ripristino): scegli il backup da una destinazione o carica un file, inserisci la password
se è cifrato. fwlog lo decomprime in `/srv/fwlog/restore`, crea gli indici per le ricerche
e la dashboard passa in **consultazione**: una barra in alto indica quale backup stai
guardando; firewall, server, registro accessi, filtri ed **Esporta CSV** funzionano come
sempre ma sui dati del backup. I dati attuali non vengono toccati, la ricezione continua
e i pulsanti che modificano qualcosa sono nascosti.

**Torna ai dati attuali** lascia il backup aperto (si può riprendere con **Consulta**
dalla barra); **Chiudi il backup** elimina la copia decompressa e libera lo spazio. Il
backup aperto viene chiuso anche preparando un altro ripristino o riavviando fwlog.

### Ricostruire la macchina da zero

1. Prepara la VM e il disco dati come alle sezioni 1 e 2, scarica il repository.
2. Copia sulla VM il backup da ripristinare (dal NAS, dal cloud o da un disco), poi:
   ```bash
   sudo RESTORE=/root/fwlog-fwlog01-registro-admin-20261117-023000.fwbk ./install.sh
   ```
   Lo script chiede la password (se cifrato), mostra il contenuto e chiede conferma.
   Ripristina il database e, se non ci sono già, certificato TLS e `fwlog.env` della
   macchina originale: password della dashboard invariata e **agenti Windows funzionanti
   senza reinstallazione** (se la VM ha lo stesso indirizzo).
3. Monta di nuovo eventuali dischi o NAS usati come destinazione e riavvia fwlog: job e
   pianificazioni sono già al loro posto.

In alternativa: installazione normale, poi dalla dashboard **Importa configurazione**
(file JSON) e **Ripristina…** dalla destinazione. In questo caso certificato e password
sono nuovi: gli agenti Windows vanno reinstallati con un nuovo token.

Da riga di comando, a servizio fermo:

```bash
sudo systemctl stop fwlog
sudo python3 /opt/fwlog/fwlog.py restore --info FILE.fwbk     # solo contenuto
sudo python3 /opt/fwlog/fwlog.py restore --replace FILE.fwbk  # il database attuale viene rinominato
sudo systemctl start fwlog
```

---

## 12. Test con test-sender.py

`test-sender.py` invia un esempio di log per ogni formato supportato:

```bash
python3 test-sender.py 192.168.200.56            # UDP
python3 test-sender.py 192.168.200.56 --tcp      # TCP
python3 test-sender.py 192.168.200.56 -n 50000   # prova di carico
```

Per gli accessi dei server Windows, crea un server dalla dashboard e usa il suo token:

```bash
python3 test-sender.py https://192.168.200.56:10443 --win <token>
```

Vengono inviati 15 eventi di esempio come li manda l'agente (accesso RDP, password errata,
blocco, aggiunta a Domain Admins, registro cancellato…); ripetendo il comando se ne
aggiungono altri.

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

## 13. Limiti noti

- **Ora di ricezione**, non quella del firewall: gli orologi e i formati data dei
  dispositivi sono troppo inaffidabili. Un ritardo di rete o di coda sposta di poco l'ora.
- I firewall sono identificati dall'**IP sorgente** dei pacchetti: due firewall dietro lo
  stesso NAT risultano uno solo; un firewall che cambia IP compare come nuovo.
- Niente syslog su TLS (porta 6514).
- Un solo utente per la dashboard.
- Registro accessi: solo accessi riusciti. I login ai firewall sono riconosciuti solo per
  i formati elencati nella sezione 6 e solo se il firewall invia anche gli eventi di sistema.
- Durante un backup la ricezione continua: nelle prove, a 3.000 e 8.000 msg/s costanti
  nessun messaggio perso; con raffiche estreme (decine di migliaia di msg/s su 2 CPU) il
  kernel può scartare parte dei pacchetti UDP (meglio TCP, o pianificare di notte).
- Backup: completi, non incrementali. Per i log dei firewall (molti GB) conviene una
  frequenza settimanale. Nessuna firma dei backup: l'inalterabilità va ottenuta sulla
  destinazione (Object Lock su S3, snapshot immutabili sul NAS).
- MikroTik non indica l'azione nel messaggio (vedi `log-prefix`); Cisco ASA registra sia
  apertura sia chiusura delle connessioni (`Built`/`Teardown`), entrambe come `allow`.
- Server Windows: l'agente non è a prova di amministratore malintenzionato, che può
  disattivare l'attività pianificata o cancellare il registro Security. Gli eventi già
  inviati restano però su fwlog, la cancellazione del registro compare come evento
  critico e un agente muto diventa rosso nella dashboard.
- Server Windows: si registrano gli accessi, non le azioni svolte durante la sessione.
  Con NLA attivo i tentativi RDP falliti risultano accessi di tipo «Rete».
- Pensato per piccole e medie aziende, fino a qualche migliaio di messaggi al secondo.
  Oltre conviene una soluzione come Graylog o basata su ClickHouse.

## Licenza

fwlog è software libero, distribuito con la licenza **GNU General Public License versione 3**
(GPL-3.0): puoi usarlo, studiarlo, modificarlo e ridistribuirlo, anche a scopo commerciale.
Chi distribuisce fwlog o una sua versione modificata deve farlo con la stessa licenza e
fornire il codice sorgente. Il testo completo è nel file [LICENSE](LICENSE).

fwlog è fornito «così com'è», senza alcuna garanzia (sezioni 15 e 16 della licenza).
