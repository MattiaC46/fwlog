#!/usr/bin/env python3
"""
fwlog - collettore syslog minimale per firewall, con dashboard web.

Riceve syslog su UDP e TCP, estrae i campi principali (sorgente, destinazione,
porte, protocollo, azione, interfacce, zone, regola) dai formati piu' comuni
(pfSense/OPNsense, FortiGate, Sophos, Palo Alto, Cisco ASA/FTD, MikroTik,
SonicWall, iptables/UFW/UniFi e in generale qualsiasi log chiave=valore) e li
salva in SQLite sul disco dati. Serve una dashboard web con filtri.

Riceve inoltre via HTTPS (POST /api/ingest, token per server) gli eventi di
accesso degli amministratori inviati dall'agente PowerShell dei server Windows
(agent/fwlog-agent.ps1).

Usa solo la libreria standard di Python 3: nessuna dipendenza da installare.
Configurazione tramite variabili d'ambiente (vedi /etc/fwlog/fwlog.env).
"""

import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import queue
import re
import secrets
import shutil
import signal
import socket
import socketserver
import sqlite3
import ssl
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# --------------------------------------------------------------------------
# Configurazione
# --------------------------------------------------------------------------
E = os.environ.get
DATA_DIR = E("FWLOG_DATA_DIR", "/srv/fwlog")
DB_PATH = os.path.join(DATA_DIR, "fwlog.db")
SYSLOG_BIND = E("FWLOG_SYSLOG_BIND", "0.0.0.0")
SYSLOG_UDP = int(E("FWLOG_SYSLOG_UDP", "514"))      # 0 = disattivato
SYSLOG_TCP = int(E("FWLOG_SYSLOG_TCP", "514"))      # 0 = disattivato
WEB_BIND = E("FWLOG_WEB_BIND", "0.0.0.0")
WEB_PORT = int(E("FWLOG_WEB_PORT", "10443"))
WEB_USER = E("FWLOG_WEB_USER", "admin")
WEB_PASS = E("FWLOG_WEB_PASS", "")
TLS_CERT = E("FWLOG_TLS_CERT", "")
TLS_KEY = E("FWLOG_TLS_KEY", "")
RETENTION_DAYS = int(E("FWLOG_RETENTION_DAYS", "90"))   # 0 = nessun limite di giorni
MIN_FREE_GB = float(E("FWLOG_MIN_FREE_GB", "2"))        # spazio minimo da lasciare libero
def _parse_sources(text):
    """IP o subnet separati da virgola. Le voci non valide vengono scartate e
    segnalate (log e dashboard): un errore di battitura non deve fermare il servizio."""
    nets, bad = [], []
    for s in text.split(","):
        s = s.strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s.strip("[]"), strict=False))
        except ValueError:
            bad.append(s[:60])
    return nets, bad


ALLOWED_SOURCES, BAD_SOURCES = _parse_sources(E("FWLOG_ALLOWED_SOURCES", ""))
REJECTED_IPS_MAX = 50   # sorgenti rifiutate ricordate (per la dashboard)
STATIC_DIR = E("FWLOG_STATIC_DIR",
               os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))
AGENT_DIR = E("FWLOG_AGENT_DIR",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent"))
QUEUE_MAX = int(E("FWLOG_QUEUE_MAX", "200000"))
# conservazione predefinita degli accessi admin dei server Windows (il Garante
# privacy chiede almeno 6 mesi per i log di accesso degli amministratori di sistema)
WIN_RETENTION_DAYS = int(E("FWLOG_WIN_RETENTION_DAYS", "365"))
INGEST_MAX = 4 * 1024 * 1024   # dimensione massima di un invio dell'agente
WIN_MAX_EVENTS = 1000          # eventi massimi per invio
MAX_RAW = 8192
MAX_FRAME = 65536      # dimensione massima di un messaggio syslog su TCP
MAX_TCP_CONN = 500     # connessioni syslog TCP contemporanee
DELETED = "deleted:"   # prefisso dell'ip di un firewall in eliminazione
BATCH = 5000
DEL_BLOCK = 20000
MAX_RETENTION = 36500

log = logging.getLogger("fwlog")

# --------------------------------------------------------------------------
# Indirizzi IP
# --------------------------------------------------------------------------
def norm_ip(s):
    """Indirizzo in forma canonica (IPv4-mapped -> IPv4), oppure None."""
    if not s:
        return None
    s = s.strip().strip("[]").split("%")[0]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a)


def _key(version, n):
    return f"4{n:08x}" if version == 4 else f"6{n:032x}"


def ip_key(addr):
    """Chiave ordinabile: confronto tra stringhe == confronto numerico.
    Permette di filtrare per subnet con un semplice BETWEEN su indice."""
    a = ipaddress.ip_address(addr)
    return _key(a.version, int(a))


def ip_condition(cols, value):
    value = value.strip()
    if "/" in value:
        try:
            n = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"subnet non valida: {value}")
        lo = _key(n.version, int(n.network_address))
        hi = _key(n.version, int(n.broadcast_address))
        return "(" + " OR ".join(f"{c} BETWEEN ? AND ?" for c in cols) + ")", [lo, hi] * len(cols)
    a = norm_ip(value)
    if not a:
        raise ValueError(f"indirizzo non valido: {value}")
    return "(" + " OR ".join(f"{c} = ?" for c in cols) + ")", [ip_key(a)] * len(cols)

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
PROTO_NUM = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp", "47": "gre",
             "50": "esp", "51": "ah", "58": "ipv6-icmp", "89": "ospf",
             "103": "pim", "112": "vrrp", "132": "sctp"}
ALLOW = {"accept", "accepted", "allow", "allowed", "pass", "permit", "permitted",
         "forward", "close", "timeout", "built", "teardown", "start", "a"}
DENY = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject",
        "rejected", "reset-both", "reset-client", "reset-server", "d", "r",
        "discard", "discarded"}


def norm_action(v):
    if not v:
        return None
    v = v.strip().strip('"').lower()
    if v in ("na", "n/a", "none", "-", ""):
        return None
    if v in ALLOW:
        return "allow"
    if v in DENY:
        return "deny"
    return v or None


def norm_proto(v):
    if not v:
        return None
    v = v.strip().strip('"').lower().split("/")[0].split(" ")[0]
    return PROTO_NUM.get(v, v) or None


RE_PRI = re.compile(r"<(\d{1,3})>")
RE_5424 = re.compile(r"1 (\S+) (\S+) (\S+) (\S+) (\S+) ?")
RE_3164 = re.compile(
    r"(?:[A-Z][a-z]{2} +\d{1,2}(?: \d{4})? \d\d:\d\d:\d\d(?:\.\d+)?|\d{4}-\d\d-\d\d[T ]\S+):?\s+"
    r"(?:(\S+)\s+)?([\w\-./]+?)(?:\[\d+\])?:\s")


def _nil(v):
    return None if (v is None or v == "-") else v


def _strip_sd(s):
    """Rimuove la parte STRUCTURED-DATA di un messaggio RFC 5424."""
    if s.startswith("-"):
        return s[1:].lstrip()
    i = 0
    while i < len(s) and s[i] == "[":
        j, esc = i + 1, False
        while j < len(s):
            c = s[j]
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == "]":
                break
            j += 1
        i = j + 1
    return s[i:].lstrip()


def parse_header(text):
    """Ritorna (severity, host, programma, corpo del messaggio)."""
    sev = None
    pos = 0
    m = RE_PRI.match(text)
    if m:
        sev = int(m.group(1)) & 7
        pos = m.end()
    m = RE_5424.match(text, pos)
    if m:
        return sev, _nil(m.group(2)), _nil(m.group(3)), _strip_sd(text[m.end():])
    m = RE_3164.match(text, pos)
    if m:
        return sev, m.group(1), m.group(2), text[m.end():]
    return sev, None, None, text[pos:]


# pfSense / OPNsense (filterlog, CSV)
RE_FILTERLOG = re.compile(
    r"(\d*,\d*,[^,\s]*,[^,\s]*,[^,\s]*,[^,\s]*,"
    r"(?:pass|block|match|reject|scrub|nat|rdr|binat),(?:in|out),[46],\S*)")


def p_filterlog(body):
    m = RE_FILTERLOG.search(body)
    if not m:
        return None
    f = m.group(1).split(",")
    g = lambda i: f[i] if i < len(f) else ""
    r = {"rule": g(3) or g(0), "action": g(6)}
    r["in_if" if g(7) == "in" else "out_if"] = g(4)
    if g(8) == "4":
        proto, r["src"], r["dst"], base = g(16), g(18), g(19), 20
    else:
        proto, r["src"], r["dst"], base = g(12), g(15), g(16), 17
    r["proto"] = proto
    if proto.lower() in ("tcp", "udp", "sctp"):
        r["sport"], r["dport"] = g(base), g(base + 1)
    return r


# Palo Alto (CSV, log TRAFFIC/THREAT)
RE_PAN = re.compile(r"(?:^|\s)(\d+,\d{4}/\d\d/\d\d \d\d:\d\d:\d\d,[^,]*,(?:TRAFFIC|THREAT),.*)$")


def p_paloalto(body):
    m = RE_PAN.search(body)
    if not m:
        return None
    f = next(csv.reader([m.group(1)]))
    g = lambda i: f[i] if i < len(f) else ""
    return {"src": g(7), "dst": g(8), "rule": g(11), "src_zone": g(16),
            "dst_zone": g(17), "in_if": g(18), "out_if": g(19), "sport": g(24),
            "dport": g(25), "proto": g(29), "action": g(30)}


# Cisco ASA / FTD
RE_ASA = re.compile(r"%(?:ASA|FTD|FWSM|PIX)-\d-\d+:\s*(.*)")
RE_ASA_FLOW = re.compile(
    r"\b(?:for|src|from)\s+(?:([\w\-.]+):)?([0-9a-fA-F:.]+)/(\d+).*?"
    r"\b(?:to|dst)\s+(?:([\w\-.]+):)?([0-9a-fA-F:.]+)/(\d+)")
RE_ASA_ACL = re.compile(
    r"access-list (\S+) (permitted|denied|est-allowed) (\w+) ([\w\-.]+)/([0-9a-fA-F:.]+)"
    r"\((\d+)\) -> ([\w\-.]+)/([0-9a-fA-F:.]+)\((\d+)\)")
RE_ASA_PROTO = re.compile(r"\b(tcp|udp|icmp|gre|esp|TCP|UDP|ICMP|GRE|ESP)\b")
RE_ASA_RULE = re.compile(r'access-(?:group|list) "?([\w\-.]+)')


def p_asa(body):
    m = RE_ASA.search(body)
    if not m:
        return None
    msg = m.group(1)
    a = RE_ASA_ACL.search(msg)
    if a:
        return {"rule": a.group(1), "action": a.group(2), "proto": a.group(3),
                "in_if": a.group(4), "src": a.group(5), "sport": a.group(6),
                "out_if": a.group(7), "dst": a.group(8), "dport": a.group(9)}
    r = {}
    f = RE_ASA_FLOW.search(msg)
    if f:
        r.update(in_if=f.group(1), src=f.group(2), sport=f.group(3),
                 out_if=f.group(4), dst=f.group(5), dport=f.group(6))
    p = RE_ASA_PROTO.search(msg)
    if p:
        r["proto"] = p.group(1)
    if re.search(r"\b(Deny|denied|Dropping|discarded)\b", msg):
        r["action"] = "deny"
    elif re.search(r"\b(Built|Teardown|permitted)\b", msg):
        r["action"] = "allow"
    rr = RE_ASA_RULE.search(msg)
    if rr:
        r["rule"] = rr.group(1)
    return r or None


# MikroTik RouterOS
_MT_IP = r"(\[[0-9a-fA-F:]+\]|[\d.]+)"
RE_MT = re.compile(
    r"(\S+): in:(\([^)]*\)|[^,\s]+) out:(\([^)]*\)|[^,\s]+),.*?proto (\w+)(?: \([^)]*\))?, "
    + _MT_IP + r"(?::(\d+))?->" + _MT_IP + r"(?::(\d+))?")


def p_mikrotik(body):
    m = RE_MT.search(body)
    if not m:
        return None
    out_if = m.group(3)
    return {"rule": m.group(1), "in_if": m.group(2),
            "out_if": None if out_if.startswith("(") else out_if,
            "proto": m.group(4), "src": m.group(5), "sport": m.group(6),
            "dst": m.group(7), "dport": m.group(8)}


# Generico chiave=valore (FortiGate, Sophos, SonicWall, Zyxel, iptables/UFW, ...)
RE_KV = re.compile(r'([A-Za-z_][\w\-.]*)=("(?:[^"\\]|\\.)*"|\S*)')
KV_FIELDS = {
    "src": ["srcip", "src_ip", "src", "source_ip", "sourceip", "src_addr", "srcaddr"],
    "dst": ["dstip", "dst_ip", "dst", "destination_ip", "destinationip", "dst_addr", "dstaddr"],
    "sport": ["srcport", "src_port", "spt", "sport", "source_port"],
    "dport": ["dstport", "dst_port", "dpt", "dport", "destination_port"],
    "proto": ["proto", "protocol", "ipproto", "ip_protocol"],
    "action": ["action", "act", "fw_action", "disposition", "log_subtype", "status"],
    "in_if": ["srcintf", "in_interface", "in_intf", "inif", "src_interface",
              "srcif", "iif", "in", "interface"],
    "out_if": ["dstintf", "out_interface", "out_intf", "outif", "dst_interface",
               "dstif", "oif", "out"],
    "src_zone": ["srczone", "src_zone", "from_zone", "fromzone", "srczonename", "srcintfrole"],
    "dst_zone": ["dstzone", "dst_zone", "to_zone", "tozone", "dstzonename", "dstintfrole"],
    "rule": ["policyid", "fw_rule_id", "rule_id", "ruleid", "rule", "rulename",
             "policyname", "policy_id"],
}
RE_IP_PORT_IF = re.compile(r"^([\d.]+):(\d+)(?::(\S+))?$")
RE_TAG_ACTION = re.compile(r"\[(?:UFW )?(BLOCK|ALLOW|DROP|ACCEPT|REJECT|AUDIT)\]", re.I)
RE_UNIFI_ACTION = re.compile(r"\[[\w\-]+-([ADR])\]")


def p_kv(body):
    kv = {}
    for k, v in RE_KV.findall(body):
        k = k.lower()
        if k not in kv:
            kv[k] = v[1:-1] if v.startswith('"') else v
    if not kv:
        return None
    r = {}
    for field, aliases in KV_FIELDS.items():
        for a in aliases:
            if kv.get(a):
                r[field] = kv[a]
                break
    if "src" not in r and "dst" not in r:
        return None
    # SonicWall / Zyxel: ip:porta[:interfaccia]
    for side, port, iface in (("src", "sport", "in_if"), ("dst", "dport", "out_if")):
        v = r.get(side)
        if v and not norm_ip(v):
            m = RE_IP_PORT_IF.match(v)
            if m:
                r[side] = m.group(1)
                r.setdefault(port, m.group(2))
                if m.group(3):
                    r.setdefault(iface, m.group(3))
    if "action" not in r:
        m = RE_TAG_ACTION.search(body) or RE_UNIFI_ACTION.search(body)
        if m:
            r["action"] = m.group(1)
    return r


PARSERS = (p_filterlog, p_paloalto, p_asa, p_mikrotik, p_kv)


def _port(v):
    try:
        n = int(v)
        return n if 0 <= n <= 65535 else None
    except (TypeError, ValueError):
        return None


def _txt(v):
    if v is None:
        return None
    v = str(v).strip().strip('"')
    return v[:64] or None


def parse_fields(body):
    for p in PARSERS:
        try:
            r = p(body)
        except Exception:
            r = None
        if r:
            return {
                "src": norm_ip(r.get("src")), "dst": norm_ip(r.get("dst")),
                "sport": _port(r.get("sport")), "dport": _port(r.get("dport")),
                "proto": norm_proto(r.get("proto")), "action": norm_action(r.get("action")),
                "in_if": _txt(r.get("in_if")), "out_if": _txt(r.get("out_if")),
                "src_zone": _txt(r.get("src_zone")), "dst_zone": _txt(r.get("dst_zone")),
                "rule": _txt(r.get("rule")),
            }
    return {}

# --------------------------------------------------------------------------
# Eventi Windows (accessi degli amministratori)
# --------------------------------------------------------------------------
# L'agente sceglie quali eventi inviare (solo account amministratori) e manda i
# campi EventData cosi' come sono; qui vengono interpretati, cosi' il significato
# si aggiorna senza reinstallare gli agenti.
NTSTATUS = {
    "0xc000006a": "password errata", "0xc0000064": "utente inesistente",
    "0xc000006f": "fuori dall'orario consentito", "0xc0000070": "workstation non autorizzata",
    "0xc0000071": "password scaduta", "0xc0000072": "account disabilitato",
    "0xc0000193": "account scaduto", "0xc0000224": "cambio password obbligatorio",
    "0xc0000234": "account bloccato", "0xc000015b": "tipo di accesso non consentito",
    "0xc0000133": "orologio non sincronizzato con il DC", "0xc000006e": "restrizione dell'account",
    "0xc0000413": "autenticazione non consentita su questo computer",
    "0xc000005e": "nessun server di accesso disponibile", "0xc0000371": "account locale senza segreto",
}
KERBEROS = {
    "0x6": "utente inesistente", "0x12": "account disabilitato, scaduto o bloccato",
    "0x17": "password scaduta", "0x18": "password errata", "0x25": "orologio non sincronizzato",
    "0xc": "restrizione dell'account",
}
AUDIT_CHANGES = {"%%8448": "successo rimosso", "%%8449": "successo aggiunto",
                 "%%8450": "errore rimosso", "%%8451": "errore aggiunto"}
AUDIT_SUBCAT = {
    "0cce9215-69ae-11d9-bed3-505054503030": "Accesso",
    "0cce9216-69ae-11d9-bed3-505054503030": "Disconnessione",
    "0cce9217-69ae-11d9-bed3-505054503030": "Blocco account",
    "0cce921b-69ae-11d9-bed3-505054503030": "Accesso speciale",
    "0cce921c-69ae-11d9-bed3-505054503030": "Altri eventi di accesso/disconnessione",
    "0cce922f-69ae-11d9-bed3-505054503030": "Modifica dei criteri di controllo",
    "0cce9235-69ae-11d9-bed3-505054503030": "Gestione account utente",
    "0cce9237-69ae-11d9-bed3-505054503030": "Gestione gruppi di sicurezza",
    "0cce923f-69ae-11d9-bed3-505054503030": "Convalida credenziali",
    "0cce9242-69ae-11d9-bed3-505054503030": "Servizio di autenticazione Kerberos",
}
# event_id -> (tipo, esito, critico)
WIN_EVENTS = {
    4624: ("logon", "ok", 0), 4625: ("logon_fail", "fail", 0), 4634: ("logoff", None, 0),
    4647: ("logoff", None, 0), 4648: ("explicit", "ok", 0), 4778: ("rdp_reconnect", "ok", 0),
    4779: ("rdp_disconnect", None, 0), 4771: ("logon_fail", "fail", 0),
    4776: ("logon_fail", "fail", 0), 4740: ("lockout", "fail", 0), 4767: ("unlock", None, 0),
    4723: ("password_change", None, 0), 4724: ("password_reset", None, 0),
    4722: ("account_enabled", None, 0), 4725: ("account_disabled", None, 0),
    4726: ("account_deleted", None, 0),
    4728: ("group_add", None, 1), 4732: ("group_add", None, 1), 4756: ("group_add", None, 1),
    4729: ("group_remove", None, 0), 4733: ("group_remove", None, 0), 4757: ("group_remove", None, 0),
    1102: ("log_cleared", None, 1), 4719: ("audit_policy", None, 1),
}
RE_CN = re.compile(r"^CN=((?:\\.|[^,])+)", re.I)


def _wv(d, k):
    v = d.get(k)
    if v is None:
        return None
    v = str(v).strip()
    return None if v in ("", "-") else v


def _split_acct(name, domain=None):
    """'DOM\\utente' o 'utente@dom' -> (utente, dominio)."""
    if not name:
        return None, domain
    if "\\" in name:
        domain, name = name.split("\\", 1)
    elif "@" in name:
        name, domain = name.split("@", 1)
    return name, domain


def _subject(d):
    n, dom = _wv(d, "SubjectUserName"), _wv(d, "SubjectDomainName")
    return f"{dom}\\{n}" if n and dom else n


def win_fields(eid, d, elev=False):
    """Campi normalizzati di un evento Windows; None se l'evento non e' gestito."""
    if eid not in WIN_EVENTS:
        return None
    kind, outcome, critical = WIN_EVENTS[eid]
    r = {"kind": kind, "outcome": outcome, "critical": critical, "elevated": 0,
         "account": None, "domain": None, "logon_type": None, "src_ip": None, "src_host": None,
         "actor": None, "target": None, "reason": None, "auth": None, "logon_id": None}
    lt = _wv(d, "LogonType")
    r["logon_type"] = int(lt) if lt and lt.isdigit() else None
    r["src_ip"] = norm_ip(_wv(d, "IpAddress") or _wv(d, "ClientAddress"))
    r["src_host"] = _wv(d, "WorkstationName") or _wv(d, "Workstation") or _wv(d, "ClientName")
    r["auth"] = _wv(d, "AuthenticationPackageName") or _wv(d, "PackageName")
    r["logon_id"] = _wv(d, "TargetLogonId") or _wv(d, "LogonID")
    if eid in (4778, 4779):
        r["account"], r["domain"] = _wv(d, "AccountName"), _wv(d, "AccountDomain")
    elif eid in (4728, 4729, 4732, 4733, 4756, 4757):
        # account = membro aggiunto/rimosso, target = gruppo
        m = _wv(d, "_member")
        if not m:
            cn = RE_CN.match(_wv(d, "MemberName") or "")
            m = cn.group(1).replace("\\", "") if cn else _wv(d, "MemberSid")
        r["account"], r["domain"] = _split_acct(m)
        g, gd = _wv(d, "TargetUserName"), _wv(d, "TargetDomainName")
        r["target"] = f"{gd}\\{g}" if g and gd else g
    elif eid in (1102, 4719):
        r["account"], r["domain"] = _wv(d, "SubjectUserName"), _wv(d, "SubjectDomainName")
    else:
        r["account"], r["domain"] = _split_acct(_wv(d, "TargetUserName"), _wv(d, "TargetDomainName"))
    if eid in (4648, 4740, 4767, 4723, 4724, 4722, 4725, 4726,
               4728, 4729, 4732, 4733, 4756, 4757):
        r["actor"] = _subject(d)
    if eid == 4648:
        r["target"] = _wv(d, "TargetServerName")
    elif eid == 4740:
        # in 4740 TargetDomainName e' il computer da cui arrivano i tentativi
        r["src_host"], r["domain"] = _wv(d, "TargetDomainName"), None
    elif eid == 4625:
        st, sub = (_wv(d, "Status") or "").lower(), (_wv(d, "SubStatus") or "").lower()
        r["reason"] = NTSTATUS.get(sub) or NTSTATUS.get(st) or (sub if sub not in ("", "0x0") else st) or None
    elif eid == 4771:
        st = (_wv(d, "Status") or "").lower()
        r["reason"], r["auth"] = KERBEROS.get(st, st or None), "Kerberos"
    elif eid == 4776:
        st = (_wv(d, "Status") or "").lower()
        r["reason"], r["auth"] = NTSTATUS.get(st, st or None), "NTLM"
    elif eid == 4719:
        g = (_wv(d, "SubcategoryGuid") or "").strip("{}").lower()
        r["target"] = AUDIT_SUBCAT.get(g, g or None)
        ch = [AUDIT_CHANGES.get(c.strip(), c.strip())
              for c in (_wv(d, "AuditPolicyChanges") or "").split(",") if c.strip()]
        r["reason"] = ", ".join(ch) or None
    if eid == 4624:
        r["elevated"] = 1 if (elev or _wv(d, "ElevatedToken") == "%%1842") else 0
    for k in ("account", "domain", "src_host", "actor", "target", "reason", "auth", "logon_id"):
        if r[k]:
            r[k] = r[k][:128]
    return r


def _str_dict(v):
    if not isinstance(v, dict):
        return {}
    out = {}
    for k, x in list(v.items())[:80]:
        if x is not None and not isinstance(x, (dict, list)):
            out[str(k)[:64]] = str(x)[:1024]
    return out


def win_ingest_rows(srv_id, d, rx):
    """Valida un invio dell'agente. Restituisce (meta, righe per INSERT_EV)."""
    evs = d.get("events", [])
    if not isinstance(evs, list):
        raise ValueError("events deve essere una lista")
    if len(evs) > WIN_MAX_EVENTS:
        raise ValueError(f"troppi eventi in un invio (massimo {WIN_MAX_EVENTS})")
    meta = {k: (str(d[k])[:200] if d.get(k) is not None else None)
            for k in ("host", "domain", "os", "ver")}
    meta["is_dc"] = 1 if d.get("is_dc") is True else 0
    status = {}
    for k in ("admins", "log_mb", "gap_total", "gap_at"):
        if isinstance(d.get(k), (int, float)) and not isinstance(d.get(k), bool):
            status[k] = int(d[k])
    if isinstance(d.get("audit_missing"), list):
        status["audit_missing"] = [str(x)[:80] for x in d["audit_missing"][:20]]
    if d.get("err"):
        status["err"] = str(d["err"])[:500]
    meta["status"] = json.dumps(status, separators=(",", ":"))
    rows = []
    for ev in evs:
        if not isinstance(ev, dict):
            continue
        try:
            rid, eid, ts = int(ev["rid"]), int(ev["eid"]), int(ev["t"])
        except (KeyError, TypeError, ValueError):
            continue
        dd = _str_dict(ev.get("d"))
        f = win_fields(eid, dd, ev.get("elev") is True)
        if f is None:
            continue
        if ts < 946684800000 or ts > rx + 86400000:   # orologio del server assurdo
            ts = rx
        data = json.dumps(dd, separators=(",", ":"), ensure_ascii=False)[:MAX_RAW]
        src = f["src_ip"]
        rows.append((ts, rx, srv_id, "Security", rid, eid, f["kind"], f["outcome"], f["critical"],
                     f["elevated"], f["account"], f["domain"], f["logon_type"], src,
                     ip_key(src) if src else None, f["src_host"], f["actor"], f["target"],
                     f["reason"], f["auth"], f["logon_id"], data))
    return meta, rows


def token_hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def cert_pin(path):
    """SHA-256 del certificato (DER) in esadecimale maiuscolo: l'agente lo
    confronta con quello presentato dal server (certificato autofirmato)."""
    try:
        with open(path) as f:
            m = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", f.read(), re.S)
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(m.group(0))).hexdigest().upper()
    except Exception:
        log.warning("impossibile calcolare l'impronta del certificato %s", path)
        return None


TLS_PIN = None

# --------------------------------------------------------------------------
# Archivio (SQLite)
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS firewalls(
    id INTEGER PRIMARY KEY, ip TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
    first_seen INTEGER, last_seen INTEGER, total INTEGER NOT NULL DEFAULT 0,
    retention_days INTEGER);
CREATE TABLE IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, fw_id INTEGER NOT NULL,
    sev INTEGER, host TEXT, prog TEXT, action TEXT, proto TEXT,
    src TEXT, src_n TEXT, sport INTEGER, dst TEXT, dst_n TEXT, dport INTEGER,
    in_if TEXT, out_if TEXT, src_zone TEXT, dst_zone TEXT, rule TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS ix_logs_fw ON logs(fw_id);
CREATE INDEX IF NOT EXISTS ix_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS ix_logs_src ON logs(src_n);
CREATE INDEX IF NOT EXISTS ix_logs_dst ON logs(dst_n);
CREATE TABLE IF NOT EXISTS servers(
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, token_hash TEXT UNIQUE,
    created INTEGER, hostname TEXT, domain TEXT, ip TEXT, is_dc INTEGER, os TEXT, agent TEXT,
    status TEXT, last_seen INTEGER, last_event INTEGER, total INTEGER NOT NULL DEFAULT 0,
    retention_days INTEGER);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, rx INTEGER NOT NULL, srv_id INTEGER NOT NULL,
    chan TEXT NOT NULL, record_id INTEGER NOT NULL, event_id INTEGER NOT NULL,
    kind TEXT, outcome TEXT, critical INTEGER NOT NULL DEFAULT 0,
    elevated INTEGER NOT NULL DEFAULT 0, account TEXT, domain TEXT, logon_type INTEGER,
    src_ip TEXT, src_n TEXT, src_host TEXT, actor TEXT, target TEXT, reason TEXT,
    auth TEXT, logon_id TEXT, data TEXT,
    UNIQUE(srv_id, chan, record_id));
CREATE INDEX IF NOT EXISTS ix_events_srv_ts ON events(srv_id, ts);
CREATE INDEX IF NOT EXISTS ix_events_src ON events(src_n);
CREATE INDEX IF NOT EXISTS ix_events_account ON events(account COLLATE NOCASE);
"""
INSERT = ("INSERT INTO logs(ts,fw_id,sev,host,prog,action,proto,src,src_n,sport,"
          "dst,dst_n,dport,in_if,out_if,src_zone,dst_zone,rule,raw) "
          "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
# l'agente puo' rimandare eventi gia' ricevuti (risposta persa): UNIQUE li scarta
INSERT_EV = ("INSERT OR IGNORE INTO events(ts,rx,srv_id,chan,record_id,event_id,kind,outcome,"
             "critical,elevated,account,domain,logon_type,src_ip,src_n,src_host,actor,target,"
             "reason,auth,logon_id,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
# (tabella, tabella proprietaria, colonna di collegamento)
LOG_TBL = ("logs", "firewalls", "fw_id")
EV_TBL = ("events", "servers", "srv_id")


class Store:
    def __init__(self):
        self.q = queue.Queue(QUEUE_MAX)
        self.received = 0
        self.dropped = 0
        self.rejected = 0
        self.rejected_ips = {}   # ip -> [messaggi/connessioni rifiutati, ultimo ms]
        self._rates = deque()
        self._lock = threading.Lock()
        self.fw_cache = {}
        self.deleting = {}     # fw_id -> eliminazioni di log in corso
        new = not os.path.exists(DB_PATH)
        c = self.connect()
        if new:
            c.execute("PRAGMA auto_vacuum=INCREMENTAL")
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        cols = [r["name"] for r in c.execute("PRAGMA table_info(firewalls)")]
        if "retention_days" not in cols:
            # DB creato da una versione precedente: aggiunge la colonna e riallinea
            # i contatori, che ora indicano i log conservati
            log.info("aggiornamento del database: conservazione per firewall")
            c.execute("ALTER TABLE firewalls ADD COLUMN retention_days INTEGER")
            c.execute("UPDATE firewalls SET total = (SELECT count(*) FROM logs "
                      "WHERE logs.fw_id = firewalls.id)")
        c.commit()
        c.close()
        self.thread = threading.Thread(target=self._run, name="writer", daemon=True)

    @staticmethod
    def connect(readonly=False):
        c = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=30000")
        c.execute("PRAGMA synchronous=NORMAL")
        if readonly:
            c.execute("PRAGMA query_only=1")
        return c

    # ---- ingresso (thread di rete) ----
    @staticmethod
    def allowed(ip):
        if not ALLOWED_SOURCES:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in ALLOWED_SOURCES)

    def reject(self, ip):
        """Conta un messaggio (UDP) o una connessione (TCP) da una sorgente non ammessa,
        ricordando gli ultimi IP: in dashboard si vede subito un dispositivo dimenticato."""
        now = int(time.time() * 1000)
        with self._lock:
            self.rejected += 1
            e = self.rejected_ips.get(ip)
            if e:
                e[0] += 1
                e[1] = now
                return
            if len(self.rejected_ips) >= REJECTED_IPS_MAX:
                del self.rejected_ips[min(self.rejected_ips, key=lambda k: self.rejected_ips[k][1])]
            self.rejected_ips[ip] = [1, now]

    def rejected_list(self, n=10):
        with self._lock:
            items = sorted(self.rejected_ips.items(), key=lambda x: -x[1][1])[:n]
        return [{"ip": ip, "count": c, "last": t} for ip, (c, t) in items]

    def submit(self, ip, data):
        ip = norm_ip(ip) or ip
        if not self.allowed(ip):
            self.reject(ip)
            return
        self.received += 1
        try:
            self.q.put_nowait((int(time.time() * 1000), ip, data))
        except queue.Full:
            self.dropped += 1

    def command(self, name, arg):
        self.q.put(("cmd", name, arg))

    def delete_logs(self, fid, where, args, max_id):
        with self._lock:
            self.deleting[fid] = self.deleting.get(fid, 0) + 1
        self.command("delete_logs", (fid, where, args, max_id))

    def _done_deleting(self, fid):
        with self._lock:
            n = self.deleting.get(fid, 0) - 1
            if n > 0:
                self.deleting[fid] = n
            else:
                self.deleting.pop(fid, None)

    def start(self):
        self.thread.start()

    def stop(self):
        try:
            self.q.put(None, timeout=5)
        except queue.Full:
            pass
        self.thread.join(15)

    def rates(self):
        """Messaggi nell'ultimo minuto per firewall."""
        cutoff = time.time() - 60
        out = {}
        with self._lock:
            while self._rates and self._rates[0][0] < cutoff:
                self._rates.popleft()
            for _, per_fw in self._rates:
                for k, v in per_fw.items():
                    out[k] = out.get(k, 0) + v
        return out

    # ---- thread di scrittura ----
    def _run(self):
        conn = self.connect()
        self.fw_cache = {r["ip"]: r["id"] for r in conn.execute("SELECT id, ip FROM firewalls")}
        # eliminazioni di firewall interrotte da un riavvio: le riprende
        for ip, fid in self.fw_cache.items():
            if ip.startswith(DELETED):
                self.command("delete_fw", fid)
        # eventi di server eliminati (eliminazione interrotta da un riavvio)
        for (sid,) in conn.execute("SELECT DISTINCT srv_id FROM events "
                                   "WHERE srv_id NOT IN (SELECT id FROM servers)").fetchall():
            self.command("delete_srv", sid)
        last_maint = 0.0
        while True:
            batch = []
            try:
                batch.append(self.q.get(timeout=1))
                while len(batch) < BATCH:
                    batch.append(self.q.get_nowait())
            except queue.Empty:
                pass
            rows, stop = [], False
            for item in batch:
                if item is None:
                    stop = True
                elif item[0] == "cmd":
                    if rows:
                        self._flush(conn, rows)
                        rows = []
                    self._command(conn, item[1], item[2])
                else:
                    rows.append(item)
            if rows:
                self._flush(conn, rows)
            if stop:
                conn.close()
                return
            if time.time() - last_maint > 60:
                last_maint = time.time()
                try:
                    self._maintenance(conn)
                except Exception:
                    log.exception("errore nella manutenzione")

    def _fw_id(self, conn, ip, host, ts):
        conn.execute("INSERT OR IGNORE INTO firewalls(ip,name,first_seen,last_seen) VALUES(?,?,?,?)",
                     (ip, host or ip, ts, ts))
        fid = conn.execute("SELECT id FROM firewalls WHERE ip=?", (ip,)).fetchone()[0]
        self.fw_cache[ip] = fid
        log.info("nuovo firewall: %s (%s)", ip, host or "-")
        return fid

    def _flush(self, conn, items):
        out, count, last = [], {}, {}
        try:
            for ts, ip, data in items:
                text = data.decode("utf-8", "replace").replace("\ufeff", "").strip("\x00\r\n ")
                if not text:
                    continue
                sev, host, prog, body = parse_header(text)
                f = parse_fields(body)
                fid = self.fw_cache.get(ip) or self._fw_id(conn, ip, host, ts)
                count[fid] = count.get(fid, 0) + 1
                last[fid] = ts
                src, dst = f.get("src"), f.get("dst")
                out.append((ts, fid, sev, host, prog, f.get("action"), f.get("proto"),
                            src, ip_key(src) if src else None, f.get("sport"),
                            dst, ip_key(dst) if dst else None, f.get("dport"),
                            f.get("in_if"), f.get("out_if"), f.get("src_zone"),
                            f.get("dst_zone"), f.get("rule"), text[:MAX_RAW]))
            conn.executemany(INSERT, out)
            for fid, n in count.items():
                conn.execute("UPDATE firewalls SET total=total+?, last_seen=max(coalesce(last_seen,0),?) "
                             "WHERE id=?", (n, last[fid], fid))
            conn.commit()
        except Exception:
            log.exception("errore salvando %d messaggi", len(items))
            conn.rollback()
            return
        with self._lock:
            self._rates.append((time.time(), count))

    def _delete_where(self, conn, fid, where, args, limit, tbl=LOG_TBL):
        """Elimina al massimo `limit` righe del firewall/server `fid` che soddisfano
        `where` (a blocchi, aggiornando il contatore). Restituisce quante ne ha eliminate."""
        table, owner, _ = tbl
        done = 0
        while done < limit:
            n = conn.execute(f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {where} "
                             "ORDER BY id LIMIT ?)", args + [min(DEL_BLOCK, limit - done)]).rowcount
            if n:
                conn.execute(f"UPDATE {owner} SET total=max(0, total-?) WHERE id=?", (n, fid))
            conn.commit()
            done += n
            if n < DEL_BLOCK:
                break
        return done

    def _delete_step(self, conn, name, arg, fid, where, args, tbl=LOG_TBL):
        """Elimina un blocco di righe; se ne restano rimette il comando in coda,
        per non bloccare a lungo la scrittura dei nuovi log.
        Restituisce True se l'eliminazione e' completata."""
        limit = DEL_BLOCK * 5
        if self._delete_where(conn, fid, where, args, limit, tbl) < limit:
            return True
        try:
            self.q.put_nowait(("cmd", name, arg))
            return False
        except queue.Full:
            while self._delete_where(conn, fid, where, args, limit, tbl) >= limit:
                pass
            return True

    def _ingest(self, conn, arg):
        """Salva un invio dell'agente Windows; il thread web aspetta l'esito in `box`."""
        sid, meta, rows, ip, box = arg
        try:
            if not conn.execute("SELECT 1 FROM servers WHERE id=?", (sid,)).fetchone():
                box["err"] = (401, "server eliminato")
                return
            before = conn.total_changes
            conn.executemany(INSERT_EV, rows)
            n = conn.total_changes - before
            last_ev = max((r[0] for r in rows), default=None)
            conn.execute(
                "UPDATE servers SET total=total+?, last_seen=?, ip=?, hostname=coalesce(?, hostname), "
                "domain=coalesce(?, domain), is_dc=?, os=coalesce(?, os), agent=coalesce(?, agent), "
                "status=?, last_event=CASE WHEN ? IS NULL THEN last_event "
                "ELSE max(coalesce(last_event, 0), ?) END WHERE id=?",
                (n, int(time.time() * 1000), ip, meta["host"], meta["domain"], meta["is_dc"],
                 meta["os"], meta["ver"], meta["status"], last_ev, last_ev, sid))
            conn.commit()
            box["n"] = n
        except Exception:
            log.exception("errore salvando gli eventi del server %s", sid)
            conn.rollback()
            box["err"] = (500, "errore interno, vedi journalctl -u fwlog")
        finally:
            box["ev"].set()

    def _command(self, conn, name, arg):
        try:
            if name == "ingest":
                self._ingest(conn, arg)
            elif name == "delete_srv":
                # la riga in servers e' gia' stata eliminata dal thread web (token revocato)
                if not self._delete_step(conn, name, arg, arg, "srv_id = ?", [arg], EV_TBL):
                    return
                conn.execute("PRAGMA incremental_vacuum").fetchall()
                log.info("eventi del server %s eliminati", arg)
            elif name == "delete_fw":
                # Il firewall viene prima "rinominato" (ip con prefisso DELETED): sparisce
                # dalla dashboard, i nuovi log dal suo IP creano un nuovo firewall con un
                # altro id e, dopo un riavvio, l'eliminazione riprende da qui.
                conn.execute("UPDATE firewalls SET ip=? WHERE id=?", (f"{DELETED}{arg}", arg))
                conn.commit()
                self.fw_cache = {k: v for k, v in self.fw_cache.items() if v != arg}
                if not self._delete_step(conn, name, arg, arg, "fw_id = ?", [arg]):
                    return
                conn.execute("DELETE FROM firewalls WHERE id=?", (arg,))
                conn.commit()
                conn.execute("PRAGMA incremental_vacuum").fetchall()
                log.info("firewall %s eliminato con i suoi log", arg)
            elif name == "delete_logs":
                fid, where, args, max_id = arg
                if not self._delete_step(conn, name, arg, fid, f"{where} AND id <= ?",
                                         args + [max_id]):
                    return
                conn.execute("PRAGMA incremental_vacuum").fetchall()
                self._done_deleting(fid)
                log.info("eliminazione log del firewall %s completata", fid)
        except Exception:
            log.exception("comando %s fallito", name)
            conn.rollback()
            if name == "delete_logs":
                self._done_deleting(arg[0])

    def _drop_oldest(self, conn, n, tbl=LOG_TBL):
        """Elimina le n righe piu' vecchie della tabella (log di tutti i firewall
        oppure eventi di tutti i server)."""
        table, owner, fk = tbl
        hi = conn.execute(f"SELECT max(id) FROM (SELECT id FROM {table} ORDER BY id LIMIT ?)",
                          (n,)).fetchone()[0]
        if hi is None:
            return 0
        counts = conn.execute(f"SELECT {fk}, count(*) FROM {table} NOT INDEXED WHERE id <= ? "
                              f"GROUP BY {fk}", (hi,)).fetchall()
        deleted = conn.execute(f"DELETE FROM {table} WHERE id <= ?", (hi,)).rowcount
        conn.executemany(f"UPDATE {owner} SET total=max(0, total-?) WHERE id=?",
                         [(c, f) for f, c in counts])
        conn.commit()
        return deleted

    def _maintenance(self, conn):
        deleted = 0
        # Conservazione: per firewall, retention_days NULL = predefinita, 0 = illimitata
        now = time.time()
        for fid, days in conn.execute("SELECT id, retention_days FROM firewalls").fetchall():
            days = RETENTION_DAYS if days is None else days
            if days <= 0:
                continue
            cutoff = int((now - days * 86400) * 1000)
            # id cresce con ts: trova l'ultimo id da eliminare e usa l'indice su fw_id
            row = conn.execute("SELECT id FROM logs WHERE ts < ? ORDER BY ts DESC LIMIT 1",
                               (cutoff,)).fetchone()
            if row:
                deleted += self._delete_where(conn, fid, "fw_id = ? AND id <= ?",
                                              [fid, row[0]], DEL_BLOCK * 10)
        # Eventi dei server Windows: per data dell'evento (indice srv_id, ts)
        for sid, days in conn.execute("SELECT id, retention_days FROM servers").fetchall():
            days = WIN_RETENTION_DAYS if days is None else days
            if days <= 0:
                continue
            cutoff = int((now - days * 86400) * 1000)
            deleted += self._delete_where(conn, sid, "srv_id = ? AND ts < ?", [sid, cutoff],
                                          DEL_BLOCK * 10, EV_TBL)
        # Protezione disco pieno: elimina i log piu' vecchi finche' non c'e' spazio;
        # gli accessi dei server (pochi e piu' preziosi) solo quando i log sono finiti
        for _ in range(20):
            if shutil.disk_usage(DATA_DIR).free >= MIN_FREE_GB * 1024 ** 3:
                break
            n = self._drop_oldest(conn, 50000) or self._drop_oldest(conn, 50000, EV_TBL)
            conn.execute("PRAGMA incremental_vacuum").fetchall()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            deleted += n
            if n == 0:
                break
            log.warning("spazio disco sotto %.1f GB: eliminati i %d log piu' vecchi", MIN_FREE_GB, n)
        if deleted:
            conn.execute("PRAGMA incremental_vacuum").fetchall()
            log.info("manutenzione: eliminati %d log", deleted)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()


store = None

# --------------------------------------------------------------------------
# Query per la dashboard
# --------------------------------------------------------------------------
LOG_COLS = ("id, ts, sev, host, prog, action, proto, src, sport, dst, dport, "
            "in_if, out_if, src_zone, dst_zone, rule, raw")
TEXT_FILTERS = (
    ("iface", ("in_if", "out_if")), ("in_if", ("in_if",)), ("out_if", ("out_if",)),
    ("zone", ("src_zone", "dst_zone")), ("src_zone", ("src_zone",)),
    ("dst_zone", ("dst_zone",)), ("action", ("action",)), ("proto", ("proto",)),
    ("rule", ("rule",)),
)


def _int(v, name):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ValueError(f"valore non valido per {name}: {v}")


def build_where(p):
    if not p.get("fw"):
        raise ValueError("parametro fw mancante")
    where, args = ["fw_id = ?"], [_int(p["fw"], "fw")]

    def add(name, sql, a):
        neg = p[name].strip().startswith("!")
        where.append(f"NOT coalesce({sql}, 0)" if neg else sql)
        args.extend(a)

    def val(name):
        return p[name].strip().lstrip("!").strip()

    if p.get("from"):
        where.append("ts >= ?"); args.append(_int(p["from"], "da"))
    if p.get("to"):
        where.append("ts <= ?"); args.append(_int(p["to"], "a"))
    if p.get("before"):
        where.append("id < ?"); args.append(_int(p["before"], "before"))
    if p.get("after"):
        where.append("id > ?"); args.append(_int(p["after"], "after"))
    for name, cols in (("src", ("src_n",)), ("dst", ("dst_n",)), ("ip", ("src_n", "dst_n"))):
        if p.get(name) and val(name):
            sql, a = ip_condition(cols, val(name))
            add(name, sql, a)
    for name, cols in (("sport", ("sport",)), ("dport", ("dport",)), ("port", ("sport", "dport"))):
        if p.get(name) and val(name):
            n = _int(val(name), name)
            add(name, "(" + " OR ".join(f"{c} = ?" for c in cols) + ")", [n] * len(cols))
    for name, cols in TEXT_FILTERS:
        if p.get(name) and val(name):
            v = val(name)
            add(name, "(" + " OR ".join(f"{c} = ? COLLATE NOCASE" for c in cols) + ")", [v] * len(cols))
    if p.get("q") and val("q"):
        q = val("q").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        add("q", "(raw LIKE ? ESCAPE '\\')", [f"%{q}%"])
    return " AND ".join(where), args


def api_firewalls():
    c = store.connect(readonly=True)
    try:
        rows = c.execute("SELECT id, ip, name, first_seen, last_seen, total, retention_days FROM firewalls "
                         "WHERE ip NOT LIKE ? ORDER BY name COLLATE NOCASE",
                         (DELETED + "%",)).fetchall()
    finally:
        c.close()
    rates = store.rates()
    du = shutil.disk_usage(DATA_DIR)
    db_size = sum(os.path.getsize(DB_PATH + s) for s in ("", "-wal") if os.path.exists(DB_PATH + s))
    return {
        "now": int(time.time() * 1000),
        "firewalls": [dict(r, rate=rates.get(r["id"], 0), deleting=r["id"] in store.deleting)
                      for r in rows],
        "stats": {"received": store.received, "dropped": store.dropped,
                  "rejected": store.rejected, "rejected_ips": store.rejected_list(),
                  "sources_open": not ALLOWED_SOURCES, "sources_bad": BAD_SOURCES,
                  "queue": store.q.qsize(),
                  "disk_free": du.free, "disk_total": du.total, "db_size": db_size,
                  "retention_days": RETENTION_DAYS},
    }


def api_logs(p):
    where, args = build_where(p)
    limit = max(1, min(_int(p.get("limit", 200), "limit"), 1000))
    c = store.connect(readonly=True)
    try:
        rows = c.execute(f"SELECT {LOG_COLS} FROM logs WHERE {where} ORDER BY id DESC LIMIT ?",
                         args + [limit]).fetchall()
    finally:
        c.close()
    return {"rows": [dict(r) for r in rows], "more": len(rows) == limit}


def api_logs_count(p):
    where, args = build_where(p)
    c = store.connect(readonly=True)
    try:
        return {"count": c.execute(f"SELECT count(*) FROM logs WHERE {where}", args).fetchone()[0]}
    finally:
        c.close()


def api_logs_delete(p):
    p = {k: v for k, v in p.items() if k not in ("before", "after", "limit")}
    where, args = build_where(p)
    fid = _int(p["fw"], "fw")
    c = store.connect(readonly=True)
    try:
        if not c.execute("SELECT 1 FROM firewalls WHERE id=?", (fid,)).fetchone():
            raise ValueError("firewall non trovato")
        max_id = c.execute("SELECT max(id) FROM logs").fetchone()[0] or 0
    finally:
        c.close()
    # max_id: i log ricevuti dopo la richiesta non vengono toccati
    store.delete_logs(fid, where, args, max_id)
    return {"ok": True}


def api_logs_csv(p):
    where, args = build_where(p)
    c = store.connect(readonly=True)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = [x.strip() for x in LOG_COLS.split(",")]
    w.writerow(cols)
    try:
        for r in c.execute(f"SELECT {LOG_COLS} FROM logs WHERE {where} ORDER BY id DESC LIMIT 100000", args):
            # i log sono dati non fidati: evita che Excel interpreti formule
            r = [("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
                 for v in r]
            r[1] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[1] / 1000))
            w.writerow(r)
    finally:
        c.close()
    return buf.getvalue()


def api_facets(p):
    fid = _int(p.get("fw"), "fw")
    keys = ("in_if", "out_if", "src_zone", "dst_zone", "action", "proto")
    found = {k: set() for k in keys}
    c = store.connect(readonly=True)
    try:
        for r in c.execute(f"SELECT {', '.join(keys)} FROM logs WHERE fw_id=? "
                           "ORDER BY id DESC LIMIT 20000", (fid,)):
            for k in keys:
                if r[k]:
                    found[k].add(r[k])
    finally:
        c.close()
    return {
        "iface": sorted(found["in_if"] | found["out_if"])[:200],
        "zone": sorted(found["src_zone"] | found["dst_zone"])[:200],
        "action": sorted(found["action"])[:50],
        "proto": sorted(found["proto"])[:50],
    }

# ---- server Windows ----
EV_COLS = ("id, ts, rx, event_id, kind, outcome, critical, elevated, account, domain, "
           "logon_type, src_ip, src_host, actor, target, reason, auth, logon_id, data")
EV_TEXT_FILTERS = (
    ("user", ("account",)), ("host", ("src_host",)), ("kind", ("kind",)),
    ("outcome", ("outcome",)), ("auth", ("auth",)), ("actor", ("actor",)),
    ("target", ("target",)),
)
EV_SEARCH = ("coalesce(account,'')||' '||coalesce(domain,'')||' '||coalesce(src_host,'')||' '||"
             "coalesce(actor,'')||' '||coalesce(target,'')||' '||coalesce(reason,'')||' '||"
             "coalesce(data,'')")


def _retention(v):
    """Valore di conservazione dal JSON: None = predefinita, 0 = illimitata."""
    if v is None or v == "":
        return None
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise ValueError("conservazione non valida")
    v = _int(v, "conservazione")
    if not 0 <= v <= MAX_RETENTION:
        raise ValueError(f"la conservazione deve essere tra 0 e {MAX_RETENTION} giorni")
    return v


def build_where_ev(p):
    if not p.get("srv"):
        raise ValueError("parametro srv mancante")
    where, args = ["srv_id = ?"], [_int(p["srv"], "srv")]

    def add(name, sql, a):
        neg = p[name].strip().startswith("!")
        where.append(f"NOT coalesce({sql}, 0)" if neg else sql)
        args.extend(a)

    def val(name):
        return p[name].strip().lstrip("!").strip()

    if p.get("from"):
        where.append("ts >= ?"); args.append(_int(p["from"], "da"))
    if p.get("to"):
        where.append("ts <= ?"); args.append(_int(p["to"], "a"))
    if p.get("bts") and p.get("bid"):
        # pagina successiva: ordinamento per (ts, id) decrescente
        bts, bid = _int(p["bts"], "bts"), _int(p["bid"], "bid")
        where.append("(ts < ? OR (ts = ? AND id < ?))"); args.extend([bts, bts, bid])
    if p.get("after"):
        where.append("id > ?"); args.append(_int(p["after"], "after"))
    if p.get("ip") and val("ip"):
        sql, a = ip_condition(("src_n",), val("ip"))
        add("ip", sql, a)
    if p.get("logon_type") and val("logon_type"):
        add("logon_type", "(logon_type = ?)", [_int(val("logon_type"), "tipo di accesso")])
    if p.get("critical") == "1":
        where.append("critical = 1")
    for name, cols in EV_TEXT_FILTERS:
        if p.get(name) and val(name):
            v = val(name)
            if name == "user":
                v = _split_acct(v)[0] or v
            add(name, "(" + " OR ".join(f"{c} = ? COLLATE NOCASE" for c in cols) + ")", [v] * len(cols))
    if p.get("q") and val("q"):
        q = val("q").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        add("q", f"({EV_SEARCH} LIKE ? ESCAPE '\\')", [f"%{q}%"])
    return " AND ".join(where), args


def api_servers():
    now = int(time.time() * 1000)
    c = store.connect(readonly=True)
    try:
        rows = c.execute("SELECT id, name, created, hostname, domain, ip, is_dc, os, agent, status, "
                         "last_seen, last_event, total, retention_days FROM servers "
                         "ORDER BY name COLLATE NOCASE").fetchall()
        out = []
        for r in rows:
            s = dict(r)
            try:
                s["status"] = json.loads(r["status"] or "{}")
            except ValueError:
                s["status"] = {}
            s["fail_24h"], s["critical_24h"] = c.execute(
                "SELECT coalesce(sum(outcome = 'fail'), 0), coalesce(sum(critical), 0) FROM events "
                "WHERE srv_id = ? AND ts >= ?", (r["id"], now - 86400000)).fetchone()
            out.append(s)
    finally:
        c.close()
    return {"now": now, "servers": out, "pin": TLS_PIN, "retention_days": WIN_RETENTION_DAYS}


def api_server_create(d):
    name = str(d.get("name") or "").strip()[:80]
    if not name:
        raise ValueError("indica il nome del server")
    tok = secrets.token_hex(32)   # esadecimale: un token che inizia con "-" confonderebbe PowerShell
    c = store.connect()
    try:
        cur = c.execute("INSERT INTO servers(name, token_hash, created) VALUES(?,?,?)",
                        (name, token_hash(tok), int(time.time() * 1000)))
        c.commit()
        sid = cur.lastrowid
    finally:
        c.close()
    log.info("server Windows aggiunto: %s (id %s)", name, sid)
    return {"id": sid, "token": tok, "pin": TLS_PIN}


def api_server_update(sid, d):
    sets, args, out = [], [], {"ok": True}
    if "name" in d:
        name = str(d["name"] or "").strip()[:80]
        if not name:
            raise ValueError("il nome non puo' essere vuoto")
        sets.append("name=?"); args.append(name)
    if "retention_days" in d:
        sets.append("retention_days=?"); args.append(_retention(d["retention_days"]))
    if d.get("new_token") is True:
        # il vecchio token smette subito di funzionare
        tok = secrets.token_hex(32)   # esadecimale: un token che inizia con "-" confonderebbe PowerShell
        sets.append("token_hash=?"); args.append(token_hash(tok))
        out.update(token=tok, pin=TLS_PIN)
    if not sets:
        raise ValueError("niente da modificare")
    c = store.connect()
    try:
        n = c.execute(f"UPDATE servers SET {', '.join(sets)} WHERE id=?", args + [sid]).rowcount
        c.commit()
    finally:
        c.close()
    if not n:
        return None
    if "token" in out:
        log.info("nuovo token per il server %s", sid)
    return out


def api_server_delete(sid):
    c = store.connect()
    try:
        n = c.execute("DELETE FROM servers WHERE id=?", (sid,)).rowcount
        c.commit()
    finally:
        c.close()
    if n:
        # gli eventi vengono eliminati a blocchi dal thread writer
        store.command("delete_srv", sid)
    return n


def api_events(p):
    where, args = build_where_ev(p)
    limit = max(1, min(_int(p.get("limit", 200), "limit"), 1000))
    c = store.connect(readonly=True)
    try:
        rows = c.execute(f"SELECT {EV_COLS} FROM events WHERE {where} ORDER BY ts DESC, id DESC LIMIT ?",
                         args + [limit]).fetchall()
    finally:
        c.close()
    return {"rows": [dict(r) for r in rows], "more": len(rows) == limit}


def api_events_csv(p):
    where, args = build_where_ev(p)
    cols = ["ts", "event_id", "kind", "outcome", "critical", "elevated", "account", "domain",
            "logon_type", "src_ip", "src_host", "actor", "target", "reason", "auth", "logon_id", "data"]
    c = store.connect(readonly=True)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    try:
        for r in c.execute(f"SELECT {', '.join(cols)} FROM events WHERE {where} "
                           "ORDER BY ts DESC, id DESC LIMIT 100000", args):
            r = [("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
                 for v in r]
            r[0] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[0] / 1000))
            w.writerow(r)
    finally:
        c.close()
    return buf.getvalue()


def api_events_facets(p):
    sid = _int(p.get("srv"), "srv")
    users, hosts = set(), set()
    c = store.connect(readonly=True)
    try:
        for r in c.execute("SELECT account, src_host FROM events WHERE srv_id=? "
                           "ORDER BY ts DESC LIMIT 5000", (sid,)):
            if r["account"]:
                users.add(r["account"])
            if r["src_host"]:
                hosts.add(r["src_host"])
    finally:
        c.close()
    key = str.lower
    return {"user": sorted(users, key=key)[:300], "host": sorted(hosts, key=key)[:300]}


_last_bad_token = [0.0]


def ingest_auth(header):
    """Id del server a cui appartiene il token (header Authorization: Bearer), o None."""
    if not header.startswith("Bearer "):
        return None
    tok = header[7:].strip()
    if not tok or len(tok) > 200:
        return None
    c = store.connect(readonly=True)
    try:
        r = c.execute("SELECT id FROM servers WHERE token_hash=?", (token_hash(tok),)).fetchone()
    finally:
        c.close()
    return r[0] if r else None

# --------------------------------------------------------------------------
# Server web
# --------------------------------------------------------------------------
class HttpError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


class Web(BaseHTTPRequestHandler):
    server_version = "fwlog"
    protocol_version = "HTTP/1.1"
    timeout = 60    # chiude connessioni inattive o lente

    def log_message(self, fmt, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(",", ":")).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _auth(self):
        if not WEB_PASS:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
            except Exception:
                user = pw = ""
            ok_u = hmac.compare_digest(user.encode(), WEB_USER.encode())
            ok_p = hmac.compare_digest(pw.encode(), WEB_PASS.encode())
            if ok_u and ok_p:
                return True
        self._send(401, {"error": "autenticazione richiesta"},
                   extra={"WWW-Authenticate": 'Basic realm="fwlog", charset="UTF-8"'})
        return False

    def _handle(self, fn, auth=True):
        if auth and not self._auth():
            return
        try:
            fn()
        except HttpError as e:
            self._send(e.code, {"error": str(e)})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            log.exception("errore API")
            self._send(500, {"error": "errore interno, vedi journalctl -u fwlog"})

    def do_GET(self):
        self._handle(self._get)

    def do_POST(self):
        if urlparse(self.path).path == "/api/ingest":
            # agente Windows: si autentica con il proprio token, non con la password
            return self._handle(self._ingest, auth=False)
        self._handle(self._post)

    def do_DELETE(self):
        self._handle(self._delete)

    def _get(self):
        u = urlparse(self.path)
        p = {k: v[-1] for k, v in parse_qs(u.query).items()}
        if u.path in ("/", "/index.html"):
            with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif u.path == "/api/firewalls":
            self._send(200, api_firewalls())
        elif u.path == "/api/logs":
            self._send(200, api_logs(p))
        elif u.path == "/api/logs.csv":
            name = time.strftime("fwlog-%Y%m%d-%H%M%S.csv")
            self._send(200, api_logs_csv(p), "text/csv; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{name}"'})
        elif u.path == "/api/logs/count":
            self._send(200, api_logs_count(p))
        elif u.path == "/api/facets":
            self._send(200, api_facets(p))
        elif u.path == "/api/servers":
            self._send(200, api_servers())
        elif u.path == "/api/events":
            self._send(200, api_events(p))
        elif u.path == "/api/events.csv":
            name = time.strftime("fwlog-accessi-%Y%m%d-%H%M%S.csv")
            self._send(200, api_events_csv(p), "text/csv; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{name}"'})
        elif u.path == "/api/events/facets":
            self._send(200, api_events_facets(p))
        elif u.path == "/agent/fwlog-agent.ps1":
            try:
                with open(os.path.join(AGENT_DIR, "fwlog-agent.ps1"), "rb") as f:
                    data = f.read()
            except OSError:
                return self._send(404, {"error": "agente non installato in " + AGENT_DIR})
            self._send(200, data, "application/octet-stream",
                       {"Content-Disposition": 'attachment; filename="fwlog-agent.ps1"'})
        else:
            self._send(404, {"error": "non trovato"})

    def _body_json(self, limit=65536):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ValueError("Content-Type deve essere application/json")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > limit:
            # il corpo non viene letto: la connessione va chiusa
            self.close_connection = True
            raise HttpError(413 if n > limit else 400, "richiesta troppo grande o non valida")
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ValueError("JSON non valido")
        if not isinstance(d, dict):
            raise ValueError("JSON non valido")
        return d

    def _ingest(self):
        sid = ingest_auth(self.headers.get("Authorization", ""))
        if sid is None:
            self.close_connection = True
            if time.time() - _last_bad_token[0] > 60:
                _last_bad_token[0] = time.time()
                log.warning("invio dell'agente con token non valido da %s", self.client_address[0])
            raise HttpError(401, "token non valido")
        d = self._body_json(INGEST_MAX)
        rx = int(time.time() * 1000)
        meta, rows = win_ingest_rows(sid, d, rx)
        box = {"ev": threading.Event(), "n": None, "err": None}
        ip = norm_ip(self.client_address[0]) or self.client_address[0]
        try:
            store.q.put_nowait(("cmd", "ingest", (sid, meta, rows, ip, box)))
        except queue.Full:
            raise HttpError(503, "fwlog sovraccarico, riprovare")
        # la risposta arriva solo a dati salvati: l'agente avanza solo dopo un 200
        if not box["ev"].wait(45):
            raise HttpError(503, "salvataggio non completato in tempo, riprovare")
        if box["err"]:
            raise HttpError(*box["err"])
        self._send(200, {"ok": True, "received": len(rows), "stored": box["n"]})

    def _post(self):
        path = urlparse(self.path).path
        if path == "/api/servers":
            return self._send(200, api_server_create(self._body_json()))
        m = re.fullmatch(r"/api/servers/(\d+)", path)
        if m:
            out = api_server_update(int(m.group(1)), self._body_json())
            if out is None:
                return self._send(404, {"error": "server non trovato"})
            return self._send(200, out)
        m = re.fullmatch(r"/api/firewalls/(\d+)", path)
        if not m:
            return self._send(404, {"error": "non trovato"})
        d = self._body_json()
        sets, args = [], []
        if "name" in d:
            name = str(d["name"] or "").strip()[:80]
            if not name:
                raise ValueError("il nome non puo' essere vuoto")
            sets.append("name=?"); args.append(name)
        if "retention_days" in d:
            sets.append("retention_days=?"); args.append(_retention(d["retention_days"]))
        if not sets:
            raise ValueError("niente da modificare")
        c = store.connect()
        try:
            n = c.execute(f"UPDATE firewalls SET {', '.join(sets)} WHERE id=?",
                          args + [int(m.group(1))]).rowcount
            c.commit()
        finally:
            c.close()
        if not n:
            return self._send(404, {"error": "firewall non trovato"})
        self._send(200, {"ok": True})

    def _delete(self):
        u = urlparse(self.path)
        if u.path == "/api/logs":
            return self._send(202, api_logs_delete({k: v[-1] for k, v in parse_qs(u.query).items()}))
        m = re.fullmatch(r"/api/servers/(\d+)", u.path)
        if m:
            if not api_server_delete(int(m.group(1))):
                return self._send(404, {"error": "server non trovato"})
            return self._send(202, {"ok": True})
        m = re.fullmatch(r"/api/firewalls/(\d+)", u.path)
        if not m:
            return self._send(404, {"error": "non trovato"})
        store.command("delete_fw", int(m.group(1)))
        self._send(202, {"ok": True})


# --------------------------------------------------------------------------
# Ricezione syslog
# --------------------------------------------------------------------------
def _family(bind):
    return socket.AF_INET6 if ":" in bind else socket.AF_INET


def udp_socket():
    """Creato nel thread principale: se il bind fallisce il servizio si ferma."""
    s = socket.socket(_family(SYSLOG_BIND), socket.SOCK_DGRAM)
    if _family(SYSLOG_BIND) == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    got = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    if got < 16 * 1024 * 1024:
        log.warning("buffer UDP limitato a %d KB: alzare net.core.rmem_max", got // 1024)
    s.bind((SYSLOG_BIND, SYSLOG_UDP))
    log.info("syslog UDP in ascolto su %s:%d", SYSLOG_BIND, SYSLOG_UDP)
    return s


def udp_loop(s):
    while True:
        try:
            data, addr = s.recvfrom(65535)
            store.submit(addr[0], data)
        except Exception:
            log.exception("errore ricezione UDP")


class SyslogTCP(socketserver.BaseRequestHandler):
    def handle(self):
        # la sorgente e' gia' stata verificata da TCPServer.verify_request
        ip = self.client_address[0]
        self.request.settimeout(3600)
        buf = b""
        while True:
            try:
                chunk = self.request.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            buf = self._frames(ip, buf + chunk)
        if buf.strip():
            store.submit(ip, buf)

    @staticmethod
    def _frames(ip, buf):
        """Gestisce sia l'octet-counting (RFC 6587) sia la terminazione a capo."""
        while True:
            buf = buf.lstrip(b"\r\n\x00 ")
            if not buf:
                return buf
            if buf[:1].isdigit():
                sp = buf.find(b" ", 0, 12)
                # lunghezze oltre MAX_FRAME non sono octet-counting valido: si tratta
                # il messaggio come terminato da a capo (memoria per connessione limitata)
                if sp > 0 and buf[:sp].isdigit() and int(buf[:sp]) <= MAX_FRAME:
                    n = int(buf[:sp])
                    if len(buf) < sp + 1 + n:
                        return buf
                    store.submit(ip, buf[sp + 1:sp + 1 + n])
                    buf = buf[sp + 1 + n:]
                    continue
                if sp == -1 and len(buf) < 12:
                    return buf
            nl = buf.find(b"\n")
            if nl == -1:
                if len(buf) > MAX_FRAME:
                    store.submit(ip, buf)
                    return b""
                return buf
            store.submit(ip, buf[:nl])
            buf = buf[nl + 1:]


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = _family(SYSLOG_BIND)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.slots = threading.BoundedSemaphore(MAX_TCP_CONN)
        self.last_warn = 0.0

    def verify_request(self, request, client_address):
        # sorgenti non ammesse chiuse subito: niente thread e nessun posto occupato
        # tra le MAX_TCP_CONN connessioni
        ip = norm_ip(client_address[0]) or client_address[0]
        if store.allowed(ip):
            return True
        store.reject(ip)
        return False

    def process_request(self, request, client_address):
        # oltre MAX_TCP_CONN connessioni le nuove vengono chiuse subito
        if not self.slots.acquire(blocking=False):
            if time.time() - self.last_warn > 60:
                self.last_warn = time.time()
                log.warning("troppe connessioni syslog TCP (max %d): rifiutata %s",
                            MAX_TCP_CONN, client_address[0])
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class WebServer(ThreadingHTTPServer):
    daemon_threads = True
    address_family = _family(WEB_BIND)

    def handle_error(self, request, client_address):
        # handshake TLS falliti, scanner, client che chiudono: niente traceback nel journal
        log.debug("errore connessione web da %s", client_address[0], exc_info=True)


# --------------------------------------------------------------------------
def main():
    global store, TLS_PIN
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    os.makedirs(DATA_DIR, exist_ok=True)
    store = Store()
    store.start()
    if SYSLOG_UDP:
        threading.Thread(target=udp_loop, args=(udp_socket(),), name="udp", daemon=True).start()
    if SYSLOG_TCP:
        tcp = TCPServer((SYSLOG_BIND, SYSLOG_TCP), SyslogTCP)
        threading.Thread(target=tcp.serve_forever, name="tcp", daemon=True).start()
        log.info("syslog TCP in ascolto su %s:%d", SYSLOG_BIND, SYSLOG_TCP)

    httpd = WebServer((WEB_BIND, WEB_PORT), Web)
    scheme = "http"
    if TLS_CERT and TLS_KEY:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True,
                                       do_handshake_on_connect=False)
        scheme = "https"
        TLS_PIN = cert_pin(TLS_CERT)
    if not WEB_PASS:
        log.warning("FWLOG_WEB_PASS non impostata: la dashboard e' accessibile senza password")
    for s in BAD_SOURCES:
        log.error("FWLOG_ALLOWED_SOURCES: voce non valida ignorata: %s", s)
    if ALLOWED_SOURCES:
        log.info("sorgenti syslog ammesse: %s", ", ".join(map(str, ALLOWED_SOURCES)))
    else:
        log.warning("FWLOG_ALLOWED_SOURCES vuoto: syslog accettato da qualsiasi IP")
    log.info("dashboard su %s://%s:%d  dati in %s", scheme, WEB_BIND, WEB_PORT, DATA_DIR)

    def _term(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _term)
    try:
        httpd.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        log.info("arresto: salvo i messaggi in coda...")
        store.stop()


if __name__ == "__main__":
    main()
