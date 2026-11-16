<#
fwlog-agent.ps1 - invia a fwlog gli accessi degli amministratori di questo server
(registro Security di Windows). Windows Server 2016 - 2025, PowerShell 5.1.

Un solo file: installa se stesso come attivita' pianificata (SYSTEM, ogni minuto).
Non resta nessun servizio in esecuzione: ogni minuto legge solo gli eventi nuovi,
tiene quelli che riguardano account amministratori e li invia via HTTPS a fwlog.
Avanza solo quando fwlog conferma il salvataggio: se fwlog non e' raggiungibile
gli eventi restano nel registro Security e vengono inviati al giro successivo.

Installazione (PowerShell come amministratore, nella cartella del file):
  powershell -ExecutionPolicy Bypass -File .\fwlog-agent.ps1 -Install `
      -Url https://<fwlog>:10443 -Token <token> -Pin <impronta>
  Token e impronta del certificato sono nella dashboard (Server Windows > Aggiungi).
  Opzioni: -ExcludeUser svc_backup,svc_sql   account da non registrare
           -ExtraAdmin mario.rossi           account da considerare amministratori

Prova:        powershell -ExecutionPolicy Bypass -File "C:\Program Files\fwlog\fwlog-agent.ps1" -Test
Rimozione:    powershell -ExecutionPolicy Bypass -File "C:\Program Files\fwlog\fwlog-agent.ps1" -Uninstall
Registro dell'agente: C:\ProgramData\fwlog\agent.log
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Test,
    [string]$Url,
    [string]$Token,
    [string]$Pin,
    [string[]]$ExcludeUser = @(),
    [string[]]$ExtraAdmin = @()
)

$ErrorActionPreference = 'Stop'
# da "powershell -File" gli elenchi arrivano come un'unica stringa "a,b"
$ExcludeUser = @($ExcludeUser | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$ExtraAdmin = @($ExtraAdmin | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$AgentVersion = '1.0'
$ProgDir = Join-Path $env:ProgramFiles 'fwlog'
$DataDir = Join-Path $env:ProgramData 'fwlog'
$ConfigFile = Join-Path $DataDir 'config.json'
$StateFile = Join-Path $DataDir 'state.json'
$LogFile = Join-Path $DataDir 'agent.log'
$TaskName = 'fwlog-agent'
$TaskPath = '\fwlog\'

$BatchSize = 250            # eventi per invio
$MaxScan = 200000           # record letti al massimo per giro
$FirstRunHours = 24         # al primo avvio: eventi delle ultime 24 ore
$RefreshMinutes = 30        # ogni quanto riverificare amministratori e criteri di controllo
$NetDedupSeconds = 600      # accessi di rete (tipo 3) uguali: uno ogni 10 minuti

# Eventi letti dal registro Security (4672 serve solo a riconoscere i token admin)
$EventIds = @(1102, 4624, 4625, 4634, 4647, 4648, 4672, 4719, 4722, 4723, 4724, 4725, 4726,
              4728, 4729, 4732, 4733, 4740, 4756, 4757, 4767, 4771, 4776, 4778, 4779)
$GroupEvents = @(4728, 4729, 4732, 4733, 4756, 4757)
$TargetEvents = @(4625, 4771, 4740, 4767, 4722, 4723, 4724, 4725, 4726)
$InteractiveTypes = @(2, 7, 10, 11, 12, 13)
$WellKnownAdmins = @('administrator', 'admin', 'amministratore', 'administrateur',
                     'administrador', 'root')
$SystemNames = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', '-', '')
$SystemSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-7')
# Gruppi privilegiati: Administrators, Account/Server/Print/Backup Operators,
# Remote Desktop Users, Hyper-V Administrators, Domain/Schema/Enterprise Admins,
# Group Policy Creator Owners, Key Admins, Enterprise Key Admins
$PrivGroupSid = '^S-1-5-32-(544|548|549|550|551|555|578)$|^S-1-5-21-[\d-]+-(512|518|519|520|526|527)$'
$PrivGroupName = 'admin|operator|operatori|desktop'

# Criteri di controllo necessari: GUID (indipendenti dalla lingua) e bit richiesti
# (1 = successo, 2 = errore). DcOnly: solo sui controller di dominio.
$AuditPolicies = @(
    @{ Name = 'Logon';                       Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Need = 3; DcOnly = $false },
    @{ Name = 'Logoff';                      Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Need = 1; DcOnly = $false },
    @{ Name = 'Account Lockout';             Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Need = 1; DcOnly = $false },
    @{ Name = 'Special Logon';               Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Need = 1; DcOnly = $false },
    @{ Name = 'Other Logon/Logoff Events';   Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Need = 1; DcOnly = $false },
    @{ Name = 'User Account Management';     Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Need = 1; DcOnly = $false },
    @{ Name = 'Security Group Management';   Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Need = 1; DcOnly = $false },
    @{ Name = 'Audit Policy Change';         Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Need = 1; DcOnly = $false },
    @{ Name = 'Credential Validation';       Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Need = 2; DcOnly = $true },
    @{ Name = 'Kerberos Authentication Service'; Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Need = 2; DcOnly = $true }
)

# --------------------------------------------------------------------------
# Utilita'
# --------------------------------------------------------------------------
function Write-AgentLog([string]$Message) {
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message
    if ($Test -or $Install -or $Uninstall) { Write-Host $Message }
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) {
            Move-Item -Path $LogFile -Destination "$LogFile.1" -Force
        }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Get-UnixMs([datetime]$Date) {
    return [long](($Date.ToUniversalTime() - [datetime]'1970-01-01T00:00:00').TotalMilliseconds)
}

function ConvertTo-Hashtable($Object) {
    $h = @{}
    if ($null -ne $Object) {
        foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value }
    }
    return $h
}

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path $Path)) { return $null }
    $text = [IO.File]::ReadAllText($Path)
    if (-not $text.Trim()) { return $null }
    return ConvertFrom-Json $text
}

function Write-JsonFile([string]$Path, $Object) {
    $tmp = "$Path.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $Object -Depth 5 -Compress))
    Move-Item -Path $tmp -Destination $Path -Force
}

# nome account senza dominio, minuscolo
function Get-ShortName([string]$Name) {
    if (-not $Name) { return '' }
    if ($Name.Contains('\')) { $Name = $Name.Split('\')[-1] }
    if ($Name.Contains('@')) { $Name = $Name.Split('@')[0] }
    return $Name.Trim().ToLowerInvariant()
}

function Get-LdapEscaped([string]$Value) {
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
}

# --------------------------------------------------------------------------
# TLS con verifica dell'impronta del certificato autofirmato di fwlog
# --------------------------------------------------------------------------
$PinSource = @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
public static class FwlogPin10 {
    public static string Pin = "";
    public static string Seen = "";
    public static bool Check(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        if (cert == null) { return false; }
        using (SHA256 sha = SHA256.Create()) {
            Seen = BitConverter.ToString(sha.ComputeHash(cert.GetRawCertData())).Replace("-", "");
        }
        return String.Equals(Seen, Pin, StringComparison.OrdinalIgnoreCase);
    }
    public static void Enable(string pin) {
        Pin = pin;
        ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(Check);
    }
}
'@

function Initialize-Tls($Config) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not $Config.Url.StartsWith('https://')) { return }
    if (-not ('FwlogPin10' -as [type])) {
        # compilata una volta all'installazione, poi solo caricata (meno CPU a ogni giro)
        $dll = Join-Path $ProgDir 'FwlogPin10.dll'
        if (Test-Path $dll) { Add-Type -Path $dll } else { Add-Type -TypeDefinition $PinSource }
    }
    [FwlogPin10]::Enable(($Config.Pin -replace '[^0-9A-Fa-f]', ''))
}

function Send-Payload($Config, $Payload) {
    $ProgressPreference = 'SilentlyContinue'   # con la barra di avanzamento PowerShell 5.1 e' molto lento
    $json = ConvertTo-Json -InputObject $Payload -Depth 6 -Compress
    $body = [Text.Encoding]::UTF8.GetBytes($json)
    $uri = $Config.Url.TrimEnd('/') + '/api/ingest'
    try {
        $r = Invoke-WebRequest -Uri $uri -Method Post -Body $body -UseBasicParsing -TimeoutSec 60 `
            -ContentType 'application/json; charset=utf-8' -Headers @{ Authorization = 'Bearer ' + $Config.Token }
        return (ConvertFrom-Json $r.Content)
    } catch {
        $msg = $_.Exception.Message
        $resp = $_.Exception.Response
        if ($null -ne $resp) {
            $code = [int]$resp.StatusCode
            if ($code -eq 401) { $msg = 'token non valido (rigenerarlo dalla dashboard e reinstallare)' }
            else { $msg = "HTTP $code $msg" }
        } elseif (('FwlogPin10' -as [type]) -and [FwlogPin10]::Seen -and
                  [FwlogPin10]::Seen -ne [FwlogPin10]::Pin) {
            $msg = 'impronta del certificato diversa da quella attesa: ' + [FwlogPin10]::Seen
        }
        throw "invio a $uri fallito: $msg"
    }
}

# --------------------------------------------------------------------------
# Informazioni sul server, amministratori, criteri di controllo
# --------------------------------------------------------------------------
function Get-HostInfo {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $logMb = 0
    try { $logMb = [int]((Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1MB) } catch { }
    return @{
        host = $env:COMPUTERNAME
        domain = $(if ($cs.PartOfDomain) { $cs.Domain } else { $null })
        part_of_domain = [bool]$cs.PartOfDomain
        is_dc = ($cs.DomainRole -ge 4)
        os = ('{0} ({1})' -f $os.Caption, $os.Version)
        log_mb = $logMb
    }
}

# Account amministratori (nomi brevi minuscoli). Gli errori non bloccano l'invio:
# vengono riportati alla dashboard.
function Get-AdminNames($Info, $Config, [ref]$Warning) {
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $WellKnownAdmins) { [void]$names.Add($n) }
    foreach ($n in @($Config.ExtraAdmin)) { if ($n) { [void]$names.Add((Get-ShortName $n)) } }
    $domainGroups = @()
    $warn = @()

    # Gruppo Administrators locale (su un DC e' quello del dominio)
    try {
        $sid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
        $grpName = $sid.Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $grp = [ADSI]("WinNT://$env:COMPUTERNAME/$grpName,group")
        foreach ($m in @($grp.psbase.Invoke('Members'))) {
            $path = [string]$m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
            $class = [string]$m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
            $parts = $path.Split('/')
            $name = $parts[-1]
            if ($class -eq 'User') { [void]$names.Add($name.ToLowerInvariant()) }
            elseif ($class -eq 'Group' -and $parts.Count -ge 2 -and $parts[-2] -ne $env:COMPUTERNAME) {
                $domainGroups += $name
            }
        }
    } catch { $warn += 'gruppo Administrators locale non leggibile: ' + $_.Exception.Message }

    # Dominio: membri anche indiretti di Administrators e dei gruppi di dominio presenti
    # nel gruppo locale, piu' gli account protetti (adminCount=1)
    if ($Info.part_of_domain) {
        try {
            $rootDse = [ADSI]'LDAP://RootDSE'
            $base = [string]$rootDse.Properties['defaultNamingContext'][0]
            $chain = '1.2.840.113556.1.4.1941'
            $filters = @('(adminCount=1)')
            # Administrators del dominio cercato per SID: il nome dipende dalla lingua del dominio
            $groupFilters = @('(objectSid=S-1-5-32-544)')
            foreach ($g in ($domainGroups | Select-Object -Unique)) {
                $groupFilters += "(sAMAccountName=$(Get-LdapEscaped $g))"
            }
            $gs = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$base",
                "(&(objectCategory=group)(|$($groupFilters -join '')))")
            [void]$gs.PropertiesToLoad.Add('distinguishedName')
            $gres = $gs.FindAll()
            try {
                foreach ($gr in $gres) {
                    $filters += "(memberOf:${chain}:=$(Get-LdapEscaped ([string]$gr.Properties['distinguishedname'][0])))"
                }
            } finally { $gres.Dispose() }
            $ds = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$base",
                "(&(objectCategory=person)(objectClass=user)(|$($filters -join '')))")
            $ds.PageSize = 500
            [void]$ds.PropertiesToLoad.Add('sAMAccountName')
            $res = $ds.FindAll()
            try {
                foreach ($r in $res) { [void]$names.Add(([string]$r.Properties['samaccountname'][0]).ToLowerInvariant()) }
            } finally { $res.Dispose() }
        } catch { $warn += 'interrogazione di Active Directory fallita: ' + $_.Exception.Message }
    }
    $Warning.Value = ($warn -join '; ')
    return @($names)
}

function Get-AuditMissing($Info) {
    $missing = @()
    $tmp = Join-Path $DataDir 'auditpol.csv'
    try {
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
        & auditpol.exe /backup /file:$tmp | Out-Null
        $rows = Import-Csv -Path $tmp
        foreach ($p in $AuditPolicies) {
            if ($p.DcOnly -and -not $Info.is_dc) { continue }
            $row = $rows | Where-Object { $_.'Subcategory GUID' -eq $p.Guid } | Select-Object -First 1
            $value = 0
            if ($row) { [void][int]::TryParse([string]$row.'Setting Value', [ref]$value) }
            if (($value -band $p.Need) -ne $p.Need) { $missing += $p.Name }
        }
    } catch {
        $missing += 'verifica non riuscita'
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    return $missing
}

# --------------------------------------------------------------------------
# Lettura del registro Security
# --------------------------------------------------------------------------
function ConvertTo-Compact($Record) {
    $x = [xml]$Record.ToXml()
    $d = @{}
    $ed = $x.Event.EventData
    if ($ed) {
        foreach ($n in @($ed.Data)) {
            if ($n -is [Xml.XmlElement] -and $n.HasAttribute('Name')) { $d[$n.GetAttribute('Name')] = $n.InnerText }
        }
    }
    $ud = $x.Event.UserData
    if ($ud -and $ud.FirstChild) {
        foreach ($c in $ud.FirstChild.ChildNodes) { if ($c -is [Xml.XmlElement]) { $d[$c.LocalName] = $c.InnerText } }
    }
    return @{ rid = [long]$Record.RecordId; eid = [int]$Record.Id; t = (Get-UnixMs $Record.TimeCreated); d = $d }
}

# Eventi nuovi dal piu' recente andando indietro, fino al segnalibro: la lettura
# costa quanto i record nuovi, non quanto l'intero registro.
function Get-EventQueryXml([bool]$FirstRun) {
    # Windows rifiuta le espressioni XPath con troppi 'or' (circa 22): piu' <Select>, al
    # massimo 10 Event ID ciascuno, che il registro unisce
    $time = ''
    if ($FirstRun) { $time = " and TimeCreated[timediff(@SystemTime) <= $($FirstRunHours * 3600000)]" }
    $selects = @()
    for ($i = 0; $i -lt $EventIds.Count; $i += 10) {
        $ids = $EventIds[$i..([Math]::Min($i + 9, $EventIds.Count - 1))]
        $selects += "<Select Path='Security'>*[System[(" + (($ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ")$time]]</Select>"
    }
    return "<QueryList><Query Id='0' Path='Security'>" + ($selects -join '') + '</Query></QueryList>'
}

function Read-NewEvents([long]$Bookmark, [ref]$NewBookmark, [ref]$Skipped) {
    $query = New-Object Diagnostics.Eventing.Reader.EventLogQuery('Security', [Diagnostics.Eventing.Reader.PathType]::LogName, (Get-EventQueryXml ($Bookmark -le 0)))
    $query.ReverseDirection = $true
    $reader = New-Object Diagnostics.Eventing.Reader.EventLogReader($query)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $newest = $Bookmark
    $since = if ($Bookmark -le 0) { (Get-Date).AddHours(-$FirstRunHours) } else { $null }
    $scanned = 0
    $hit = $false
    $Skipped.Value = 0
    try {
        while ($true) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            try {
                $rid = [long]$e.RecordId
                if ($scanned -eq 0) {
                    # registro ricreato o svuotato: i numeri ripartono
                    if ($Bookmark -gt 0 -and $rid -lt $Bookmark) {
                        Write-AgentLog "registro Security ricreato: riparto dal record $rid"
                        $Bookmark = 0
                        $since = (Get-Date).AddHours(-$FirstRunHours)
                    }
                    $newest = $rid
                }
                if ($Bookmark -gt 0 -and $rid -le $Bookmark) { $hit = $true; break }
                if ($null -ne $since -and $e.TimeCreated -lt $since) { break }
                $scanned++
                if ($scanned -gt $MaxScan) {
                    $Skipped.Value = 1
                    break
                }
                $out.Add((ConvertTo-Compact $e))
            } finally { $e.Dispose() }
        }
    } finally { $reader.Dispose() }
    # il record del segnalibro non c'e' piu': registro pieno e sovrascritto (o svuotato)
    # prima che gli eventi intermedi venissero letti
    if ($Bookmark -gt 0 -and -not $hit -and -not $Skipped.Value) { $Skipped.Value = 2 }
    $NewBookmark.Value = $newest
    $out.Reverse()   # in ordine cronologico
    return , $out
}

# --------------------------------------------------------------------------
# Selezione degli eventi che riguardano amministratori
# --------------------------------------------------------------------------
function Test-SystemAccount([string]$Name, [string]$Sid) {
    if (-not $Name -or $SystemNames -contains $Name) { return $true }
    if ($Name.EndsWith('$')) { return $true }                      # account computer
    if ($Name -match '^(DWM|UMFD)-\d+$') { return $true }          # sessioni di sistema
    if ($Sid -and ($SystemSids -contains $Sid -or $Sid -like 'S-1-5-90-*' -or $Sid -like 'S-1-5-96-*')) { return $true }
    return $false
}

function Resolve-MemberName([string]$Sid) {
    try {
        return (New-Object Security.Principal.SecurityIdentifier $Sid).Translate([Security.Principal.NTAccount]).Value
    } catch { return $null }
}

# $State: hashtable con admins (lista), learned, sessions, net_seen (dizionari)
function Select-AdminEvents($Events, $State, $Config) {
    $now = Get-UnixMs (Get-Date)
    $admins = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($State.admins)) { if ($n) { [void]$admins.Add($n) } }
    foreach ($n in @($State.learned.Keys)) { [void]$admins.Add($n) }
    $exclude = @($Config.ExcludeUser | ForEach-Object { Get-ShortName $_ })

    # 1) token con privilegi speciali (4672): l'evento segue il 4624 corrispondente
    $privileged = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($ev in $Events) {
        if ($ev.eid -ne 4672) { continue }
        $n = $ev.d['SubjectUserName']
        if (Test-SystemAccount $n $ev.d['SubjectUserSid']) { continue }
        [void]$privileged.Add([string]$ev.d['SubjectLogonId'])
        $short = Get-ShortName $n
        if ($exclude -notcontains $short) {
            [void]$admins.Add($short)
            $State.learned[$short] = $now
        }
    }

    $isAdmin = {
        param([string]$Name)
        $s = Get-ShortName $Name
        return ($s -and $exclude -notcontains $s -and $admins.Contains($s))
    }

    $keep = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ev in $Events) {
        $d = $ev.d
        $eid = $ev.eid
        $send = $false
        switch ($eid) {
            4624 {
                $lt = 0
                [void][int]::TryParse([string]$d['LogonType'], [ref]$lt)
                if ($lt -eq 4 -or $lt -eq 5) { break }           # attivita' pianificate e servizi
                if (Test-SystemAccount $d['TargetUserName'] $d['TargetUserSid']) { break }
                $logonId = [string]$d['TargetLogonId']
                $elev = ($d['ElevatedToken'] -eq '%%1842') -or $privileged.Contains($logonId)
                if (-not ($elev -or (& $isAdmin $d['TargetUserName']))) { break }
                if ($exclude -contains (Get-ShortName $d['TargetUserName'])) { break }
                # UAC crea due accessi collegati: si tiene solo quello con token elevato
                $linked = [string]$d['TargetLinkedLogonId']
                if (-not $elev -and $linked -and $linked -ne '0x0') { break }
                if ($lt -eq 3) {
                    $key = (Get-ShortName $d['TargetUserName']) + '|' + [string]$d['IpAddress']
                    if ($State.net_seen.ContainsKey($key) -and ($now - [long]$State.net_seen[$key]) -lt $NetDedupSeconds * 1000) { break }
                    $State.net_seen[$key] = $now
                }
                if ($InteractiveTypes -contains $lt) { $State.sessions[$logonId.ToLowerInvariant()] = $now }
                $ev['elev'] = [bool]$elev
                $send = $true
            }
            { $_ -eq 4634 -or $_ -eq 4647 } {
                $id = ([string]$d['TargetLogonId']).ToLowerInvariant()
                if ($State.sessions.ContainsKey($id)) { $State.sessions.Remove($id); $send = $true }
            }
            { $_ -eq 4778 -or $_ -eq 4779 } {
                $id = ([string]$d['LogonID']).ToLowerInvariant()
                $send = $State.sessions.ContainsKey($id) -or (& $isAdmin $d['AccountName'])
            }
            4648 {
                if (Test-SystemAccount $d['SubjectUserName'] $d['SubjectUserSid']) { break }
                $send = (& $isAdmin $d['TargetUserName']) -or (& $isAdmin $d['SubjectUserName'])
            }
            4776 {
                if ([string]$d['Status'] -eq '0x0') { break }   # solo i fallimenti
                $send = & $isAdmin $d['TargetUserName']
            }
            { $TargetEvents -contains $_ } {
                if (([string]$d['TargetUserName']).EndsWith('$')) { break }
                $send = & $isAdmin $d['TargetUserName']
            }
            { $GroupEvents -contains $_ } {
                $sid = [string]$d['TargetSid']
                if ($sid -match $PrivGroupSid -or [string]$d['TargetUserName'] -match $PrivGroupName) {
                    $ms = [string]$d['MemberSid']
                    if ($ms -and $ms -ne '-') {
                        $resolved = Resolve-MemberName $ms
                        if ($resolved) { $d['_member'] = $resolved }
                    }
                    $send = $true
                }
            }
            { $_ -eq 1102 -or $_ -eq 4719 } { $send = $true }
        }
        if ($send) { $keep.Add($ev) }
    }

    # pulizia dello stato
    foreach ($k in @($State.net_seen.Keys)) {
        if (($now - [long]$State.net_seen[$k]) -gt $NetDedupSeconds * 1000) { $State.net_seen.Remove($k) }
    }
    foreach ($k in @($State.sessions.Keys)) {
        if (($now - [long]$State.sessions[$k]) -gt 30 * 86400000) { $State.sessions.Remove($k) }
    }
    foreach ($k in @($State.learned.Keys)) {
        if (($now - [long]$State.learned[$k]) -gt 90 * 86400000) { $State.learned.Remove($k) }
    }
    return , $keep
}

# --------------------------------------------------------------------------
# Ciclo di invio
# --------------------------------------------------------------------------
function Read-State {
    $s = $null
    try { $s = Read-JsonFile $StateFile } catch { Write-AgentLog "stato illeggibile, riparto: $($_.Exception.Message)" }
    $state = ConvertTo-Hashtable $s
    foreach ($k in @('learned', 'sessions', 'net_seen')) { $state[$k] = ConvertTo-Hashtable $state[$k] }
    if (-not $state.ContainsKey('bookmark')) { $state.bookmark = 0 }
    if (-not $state.ContainsKey('admins')) { $state.admins = @() }
    if (-not $state.ContainsKey('refreshed')) { $state.refreshed = 0 }
    if (-not $state.ContainsKey('gap_total')) { $state.gap_total = 0 }
    return $state
}

function Invoke-Cycle {
    $cfgObj = Read-JsonFile $ConfigFile
    if ($null -eq $cfgObj) { throw "configurazione mancante ($ConfigFile): eseguire -Install" }
    $cfg = ConvertTo-Hashtable $cfgObj
    Initialize-Tls $cfg
    $state = Read-State
    $now = Get-UnixMs (Get-Date)

    # amministratori, informazioni e criteri di controllo: ogni $RefreshMinutes minuti
    if ($Test -or ($now - [long]$state.refreshed) -gt $RefreshMinutes * 60000 -or -not $state.info) {
        $info = Get-HostInfo
        $warn = ''
        $state.admins = Get-AdminNames $info $cfg ([ref]$warn)
        $state.audit_missing = @(Get-AuditMissing $info)
        $state.warning = $warn
        $state.info = $info
        $state.refreshed = $now
        if ($warn) { Write-AgentLog "avviso: $warn" }
        if ($state.audit_missing.Count) { Write-AgentLog ('criteri di controllo mancanti: ' + ($state.audit_missing -join ', ')) }
        # salvato subito: se fwlog non risponde non si rifanno le interrogazioni ogni minuto
        Write-JsonFile $StateFile $state
    }
    $info = ConvertTo-Hashtable $state.info

    $newBookmark = 0
    $skipped = 0
    $events = Read-NewEvents ([long]$state.bookmark) ([ref]$newBookmark) ([ref]$skipped)
    if ($skipped) {
        $state.gap_total = [long]$state.gap_total + 1
        $state.gap_at = $now
        if ($skipped -eq 1) { Write-AgentLog "troppi eventi nuovi: letti solo gli ultimi $MaxScan" }
        else { Write-AgentLog 'registro Security sovrascritto prima della lettura: alcuni eventi potrebbero mancare' }
    }
    $keep = Select-AdminEvents $events $state $cfg
    $adminCount = @($state.admins).Count + @($state.learned.Keys).Count

    $meta = @{
        host = $info.host; domain = $info.domain; is_dc = [bool]$info.is_dc; os = $info.os
        ver = $AgentVersion; admins = $adminCount; log_mb = $info.log_mb
        audit_missing = @($state.audit_missing); gap_total = [long]$state.gap_total
        err = $state.warning
    }
    if ($state.gap_at) { $meta.gap_at = [long]$state.gap_at }

    # invio a blocchi; heartbeat anche senza eventi
    $sent = 0
    $i = 0
    do {
        $chunk = @()
        if ($keep.Count) { $chunk = $keep.GetRange($i, [Math]::Min($BatchSize, $keep.Count - $i)).ToArray() }
        $payload = $meta.Clone()
        $payload.events = @($chunk)
        $r = Send-Payload $cfg $payload
        $sent += [int]$r.stored
        $i += $BatchSize
        if ($i -lt $keep.Count) {
            # blocco salvato: il segnalibro avanza fino all'ultimo evento inviato
            $state.bookmark = [long]$chunk[-1].rid
            Write-JsonFile $StateFile $state
        }
    } while ($i -lt $keep.Count)

    $state.bookmark = $newBookmark
    Write-JsonFile $StateFile $state
    if ($keep.Count -or $Test) {
        Write-AgentLog ("letti {0} eventi, inviati {1} (nuovi {2}), amministratori noti {3}" -f $events.Count, $keep.Count, $sent, $adminCount)
    }
}

# --------------------------------------------------------------------------
# Installazione e rimozione
# --------------------------------------------------------------------------
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'eseguire PowerShell come amministratore'
    }
}

function Install-Agent {
    Assert-Admin
    if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'serve PowerShell 5.1 o successivo' }
    if (-not $Url -or -not $Token) { throw 'parametri -Url e -Token obbligatori' }
    if (-not $Url.StartsWith('https://') -and -not $Url.StartsWith('http://')) { throw '-Url deve iniziare con https://' }
    if ($Url.StartsWith('https://') -and -not ($Pin -replace '[^0-9A-Fa-f]', '')) { throw 'parametro -Pin obbligatorio con https' }

    Write-AgentLog 'Copio l''agente'
    New-Item -ItemType Directory -Force -Path $ProgDir | Out-Null
    $target = Join-Path $ProgDir 'fwlog-agent.ps1'
    if ($PSCommandPath -ne $target) { Copy-Item -Path $PSCommandPath -Destination $target -Force }
    Unblock-File -Path $target -ErrorAction SilentlyContinue
    $dll = Join-Path $ProgDir 'FwlogPin10.dll'
    if (-not (Test-Path $dll)) { Add-Type -TypeDefinition $PinSource -OutputAssembly $dll -OutputType Library }

    # configurazione e stato leggibili solo da SYSTEM e Administrators (contengono il token)
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    $cfg = @{ Url = $Url.TrimEnd('/'); Token = $Token; Pin = ($Pin -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
              ExcludeUser = @($ExcludeUser); ExtraAdmin = @($ExtraAdmin) }
    Write-JsonFile $ConfigFile $cfg

    Write-AgentLog 'Configuro i criteri di controllo (auditpol)'
    $isDc = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
    foreach ($p in $AuditPolicies) {
        if ($p.DcOnly -and -not $isDc) { continue }
        $okArgs = @('/set', "/subcategory:$($p.Guid)")
        if ($p.Need -band 1) { $okArgs += '/success:enable' }
        if ($p.Need -band 2) { $okArgs += '/failure:enable' }
        & auditpol.exe @okArgs | Out-Null
    }
    # le sottocategorie hanno la precedenza sulle categorie legacy
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord

    $size = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
    if ($size -lt 256MB) {
        Write-AgentLog 'Porto il registro Security a 256 MB'
        & wevtutil.exe sl Security /ms:268435456 | Out-Null
    }

    Write-AgentLog 'Prova di invio a fwlog'
    Remove-Item -Path $StateFile -Force -ErrorAction SilentlyContinue
    $script:Test = $true
    Invoke-Cycle

    Write-AgentLog 'Creo l''attivita'' pianificata (ogni minuto, come SYSTEM)'
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$target`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Invia a fwlog gli accessi degli amministratori' -Force | Out-Null

    Write-AgentLog ''
    Write-AgentLog 'Installazione completata. Il server risulta attivo nella dashboard di fwlog.'
    if ($isDc) {
        Write-AgentLog 'Controller di dominio: se i criteri di controllo sono gestiti da GPO, vanno configurati'
        Write-AgentLog 'nella GPO (Default Domain Controllers Policy), altrimenti la GPO sovrascrive quelli locali.'
    }
}

function Uninstall-Agent {
    Assert-Admin
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $ProgDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Agente fwlog rimosso. I criteri di controllo e la dimensione del registro Security restano invariati.'
}

# --------------------------------------------------------------------------
# Avvio (non quando il file viene incluso con ". .\fwlog-agent.ps1" per i test)
# --------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ($Uninstall) { Uninstall-Agent }
        elseif ($Install) { Install-Agent }
        else { Invoke-Cycle }
    } catch {
        Write-AgentLog ('ERRORE: ' + $_.Exception.Message)
        exit 1
    }
}
