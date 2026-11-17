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
import datetime
import gzip
import hashlib
import hmac
import http.client
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
import subprocess
import sys
import threading
import tempfile
import time
import xml.etree.ElementTree as ET
import zlib
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse, urlsplit

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
# conservazione predefinita dei login degli amministratori ai firewall (registro
# accessi admin); modificabile dalla dashboard
ADMIN_RETENTION_DAYS = int(E("FWLOG_ADMIN_RETENTION_DAYS", str(WIN_RETENTION_DAYS)))
ETC_DIR = E("FWLOG_ETC_DIR", "/etc/fwlog")
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


def _kv_dict(body):
    kv = {}
    for k, v in RE_KV.findall(body):
        k = k.lower()
        if k not in kv:
            kv[k] = v[1:-1] if v.startswith('"') else v
    return kv


def p_kv(body):
    kv = _kv_dict(body)
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
# Accessi degli amministratori ai firewall (GUI web, SSH, console)
# --------------------------------------------------------------------------
# Riconosciuti nei syslog e copiati nel registro accessi admin (tabella fw_admin),
# che ha una conservazione propria: i log del firewall possono durare meno.
# Prefiltro economico: le regole sotto vengono provate solo se c'e' una di
# queste parole.
RE_ADMIN_HINT = re.compile(
    r"log(?:ged)? ?(?:in|out)|login|authenticat|Accepted |Failed |Disconnected from user|%(?:ASA|FTD)-\d-(?:60500[45]|611103)", re.I)
_AIP = r"([0-9A-Fa-f:.]+)"
# pfSense / OPNsense (webConfigurator)
RE_PF_OK = re.compile(r"Successful login for user '([^']*)' from:?\s*" + _AIP)
RE_PF_FAIL = re.compile(r"(?:webConfigurator|Web GUI) authentication error for user '([^']*)' from:?\s*" + _AIP, re.I)
RE_PF_OUT = re.compile(r"(?:User logged out|Session timed out) for user '([^']*)' from:?\s*" + _AIP)
# OPNsense (audit): "user root authenticated successfully for WebGui [...]"
RE_OPN = re.compile(r"\buser (\S+) (authenticated successfully|could not authenticate) for (\w+)")
RE_FROM_IP = re.compile(r"\bfrom:?\s*" + _AIP)
# OpenSSH (pfSense, OPNsense, Linux, UniFi...)
RE_SSH_OK = re.compile(r"Accepted (\S+) for (\S+) from " + _AIP + " port")
RE_SSH_FAIL = re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from " + _AIP + " port")
RE_SSH_OUT = re.compile(r"Disconnected from user (\S+) " + _AIP + " port")
# MikroTik: "user admin logged in from 192.168.88.10 via winbox"
RE_MT_ADM = re.compile(r"\buser (\S+) logged (in|out)(?: from " + _AIP + r")? via (\S+)")
RE_MT_FAIL = re.compile(r"login failure for user (\S+)(?: from " + _AIP + r")? via (\S+)")
# Cisco ASA / FTD
RE_ASA_LOGIN = re.compile(r"%(?:ASA|FTD)-\d-60500[45]: Login (permitted|denied) from " + _AIP +
                          r"/\d+ to \S+?:[0-9A-Fa-f:.]+/(\w+) for user \"([^\"]*)\"")
RE_ASA_OUT = re.compile(r"%(?:ASA|FTD)-\d-611103: User logged out: Uname: (\S+)")
# Palo Alto (log SYSTEM)
RE_PAN_ADM = re.compile(r"User (\S+) logged (in|out) via (\w+) from " + _AIP)
RE_PAN_FAIL = re.compile(r"failed authentication for user '([^']*)'\.?\s*(?:Reason: ([^.]*)\.)?.*?From: " + _AIP)
RE_SW_ADM = re.compile(r"Administrator (login allowed|login denied|logged out)|login denied due to bad credentials", re.I)


def _adm(kind, account, ip=None, method=None, reason=None):
    # l'IP puo' chiudere una frase ("From: 10.0.0.1.")
    return {"kind": kind, "account": account, "src_ip": ip.rstrip(".") if ip else None, "method": method,
            "reason": reason}


def _admin_kv(kv):
    """Formati chiave=valore: FortiGate, Sophos, SonicWall."""
    act = kv.get("action", "").lower()
    # FortiGate: type=event subtype=system action=login|logout
    if act in ("login", "logout") and (kv.get("subtype") == "system" or "admin" in kv.get("logdesc", "").lower()):
        m = re.match(r"(\w+)\(([^)]*)\)", kv.get("ui", ""))
        method = kv.get("method") or (m.group(1) if m else kv.get("ui"))
        ip = kv.get("srcip") or (m.group(2) if m else None)
        if act == "logout":
            return _adm("logoff", kv.get("user"), ip, method)
        ok = kv.get("status", "").lower() in ("success", "succeeded")
        reason = None if ok or kv.get("reason") in (None, "", "none") else kv.get("reason")
        return _adm("logon" if ok else "logon_fail", kv.get("user"), ip, method, reason)
    # Sophos Firewall: log_type=Event, componente GUI/Admin/CLI/SSH
    if kv.get("log_type", "").lower() == "event" and (
            kv.get("log_component", "").lower() in ("gui", "admin", "cli", "ssh", "console", "api")
            or kv.get("log_subtype", "").lower() == "admin"):
        msg, stt = kv.get("message", "").lower(), kv.get("status", "").lower()
        user = kv.get("user_name") or kv.get("user")
        method = {"gui": "https", "admin": "https"}.get(kv.get("log_component", "").lower(),
                                                         kv.get("log_component", "").lower() or None)
        if "logged out" in msg or "logout" in msg:
            return _adm("logoff", user, kv.get("src_ip"), method)
        if stt.startswith("fail") or "fail" in msg:
            return _adm("logon_fail", user, kv.get("src_ip"), method)
        if stt.startswith("success") or "logged in" in msg:
            return _adm("logon", user, kv.get("src_ip"), method)
        return None
    # SonicWall: msg="Administrator login allowed" usr="admin" src=ip:porta:iface
    m = RE_SW_ADM.search(kv.get("msg", ""))
    if m and (kv.get("usr") or kv.get("user")):
        src = (kv.get("src") or "").split(":")[0]
        what = (m.group(1) or "denied").lower()
        kind = "logoff" if "out" in what else "logon" if "allowed" in what else "logon_fail"
        proto = kv.get("proto", "")
        return _adm(kind, kv.get("usr") or kv.get("user"), src, proto.split("/")[1] if "/" in proto else None)
    return None


def parse_admin(prog, body):
    """Accesso di un amministratore al firewall, oppure None."""
    if not RE_ADMIN_HINT.search(body):
        return None
    m = RE_PF_OK.search(body)
    if m:
        return _adm("logon", m.group(1), m.group(2), "https")
    m = RE_PF_FAIL.search(body)
    if m:
        return _adm("logon_fail", m.group(1), m.group(2), "https")
    m = RE_PF_OUT.search(body)
    if m:
        return _adm("logoff", m.group(1), m.group(2), "https")
    m = RE_OPN.search(body)
    if m:
        ip = RE_FROM_IP.search(body)
        return _adm("logon" if m.group(2).startswith("auth") else "logon_fail", m.group(1),
                    ip.group(1) if ip else None, m.group(3).lower())
    if (prog or "").startswith("sshd") or "sshd" in body[:120]:
        m = RE_SSH_OK.search(body)
        if m:
            return _adm("logon", m.group(2), m.group(3), "ssh", m.group(1))
        m = RE_SSH_FAIL.search(body)
        if m:
            return _adm("logon_fail", m.group(2), m.group(3), "ssh", m.group(1))
        m = RE_SSH_OUT.search(body)
        if m:
            return _adm("logoff", m.group(1), m.group(2), "ssh")
    m = RE_ASA_LOGIN.search(body)
    if m:
        return _adm("logon" if m.group(1) == "permitted" else "logon_fail", m.group(4), m.group(2), m.group(3))
    m = RE_ASA_OUT.search(body)
    if m:
        return _adm("logoff", m.group(1).strip('",'))
    m = RE_PAN_ADM.search(body)
    if m:
        return _adm("logon" if m.group(2) == "in" else "logoff", m.group(1), m.group(4), m.group(3).lower())
    m = RE_PAN_FAIL.search(body)
    if m:
        return _adm("logon_fail", m.group(1), m.group(3), None, m.group(2))
    m = RE_MT_FAIL.search(body)
    if m:
        return _adm("logon_fail", m.group(1), m.group(2), m.group(3))
    m = RE_MT_ADM.search(body)
    if m:
        return _adm("logon" if m.group(2) == "in" else "logoff", m.group(1), m.group(3), m.group(4))
    if "=" in body:
        return _admin_kv(_kv_dict(body))
    return None


def admin_row(ts, fw_ip, fw_name, a, text):
    """Riga per INSERT_ADM da un risultato di parse_admin."""
    src = norm_ip(a["src_ip"])
    method = (_txt(a["method"]) or "").lower() or None
    return (ts, fw_ip, fw_name, a["kind"], "ok" if a["kind"] == "logon" else "fail" if a["kind"] == "logon_fail" else None,
            (_txt(a["account"]) or "")[:128] or None, src, ip_key(src) if src else None, method,
            (_txt(a["reason"]) or None), text[:2048])

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
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS fw_admin(
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, fw_ip TEXT NOT NULL, fw_name TEXT,
    kind TEXT, outcome TEXT, account TEXT, src_ip TEXT, src_n TEXT, method TEXT, reason TEXT,
    raw TEXT);
CREATE INDEX IF NOT EXISTS ix_fw_admin_ts ON fw_admin(ts);
CREATE INDEX IF NOT EXISTS ix_fw_admin_fw ON fw_admin(fw_ip, ts);
CREATE INDEX IF NOT EXISTS ix_fw_admin_src ON fw_admin(src_n);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS backup_repos(
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, type TEXT NOT NULL, config TEXT NOT NULL,
    created INTEGER);
CREATE TABLE IF NOT EXISTS backup_jobs(
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, repo_id INTEGER, contents TEXT NOT NULL,
    schedule TEXT NOT NULL, keep INTEGER NOT NULL DEFAULT 7, password TEXT,
    enabled INTEGER NOT NULL DEFAULT 1, created INTEGER, last_run INTEGER, last_status TEXT,
    last_msg TEXT, next_run INTEGER);
CREATE TABLE IF NOT EXISTS backup_runs(
    id INTEGER PRIMARY KEY, job_id INTEGER, job_name TEXT, kind TEXT, started INTEGER,
    ended INTEGER, status TEXT, msg TEXT, file TEXT, size INTEGER, repo TEXT);
"""
INSERT = ("INSERT INTO logs(ts,fw_id,sev,host,prog,action,proto,src,src_n,sport,"
          "dst,dst_n,dport,in_if,out_if,src_zone,dst_zone,rule,raw) "
          "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
# l'agente puo' rimandare eventi gia' ricevuti (risposta persa): UNIQUE li scarta
INSERT_EV = ("INSERT OR IGNORE INTO events(ts,rx,srv_id,chan,record_id,event_id,kind,outcome,"
             "critical,elevated,account,domain,logon_type,src_ip,src_n,src_host,actor,target,"
             "reason,auth,logon_id,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
INSERT_ADM = ("INSERT INTO fw_admin(ts,fw_ip,fw_name,kind,outcome,account,src_ip,src_n,method,"
              "reason,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
# (tabella, tabella proprietaria, colonna di collegamento)
LOG_TBL = ("logs", "firewalls", "fw_id")
EV_TBL = ("events", "servers", "srv_id")


def get_setting(conn, k, default=None):
    r = conn.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def admin_retention(conn):
    """Conservazione dei login admin ai firewall: impostata dalla dashboard o predefinita."""
    v = get_setting(conn, "fw_admin_retention_days")
    return ADMIN_RETENTION_DAYS if v is None else int(v)


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
        self.snapshot = 0      # backup in corso: niente checkpoint TRUNCATE (aspetterebbe)
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

    def _load_fw(self, conn):
        """Cache ip -> id dei firewall; riprende le eliminazioni interrotte."""
        self.fw_cache = {r["ip"]: r["id"] for r in conn.execute("SELECT id, ip FROM firewalls")}
        for ip, fid in self.fw_cache.items():
            if ip.startswith(DELETED):
                self.command("delete_fw", fid)

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
        # eliminazioni di firewall interrotte da un riavvio: le riprende
        self._load_fw(conn)
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

    def _fw_name(self, conn, fid):
        r = conn.execute("SELECT name FROM firewalls WHERE id=?", (fid,)).fetchone()
        return r[0] if r else None

    def _flush(self, conn, items):
        out, count, last, adm = [], {}, {}, []
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
                try:
                    a = parse_admin(prog, body)
                except Exception:
                    a = None
                if a:
                    adm.append(admin_row(ts, ip, self._fw_name(conn, fid), a, text))
            conn.executemany(INSERT, out)
            if adm:
                conn.executemany(INSERT_ADM, adm)
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

    def _restore(self, conn, arg):
        """Ripristino di un backup: ogni sezione scelta torna com'era nel backup
        ("replace"); per il registro admin "merge" aggiunge solo gli eventi mancanti.
        Gira nel thread writer: intanto i log in arrivo restano in coda."""
        path, sections, mode, box = arg
        out, attached = {}, False
        try:
            conn.commit()
            conn.execute("ATTACH DATABASE ? AS b", (path,))
            attached = True
            have = {r[0] for r in conn.execute("SELECT name FROM b.sqlite_master WHERE type='table'")}

            def copy(t, verb="INSERT", skip=(), tail=""):
                if t not in have:
                    return 0
                bcols = {r[1] for r in conn.execute(f"PRAGMA b.table_info({t})")}
                cols = ", ".join(r[1] for r in conn.execute(f"PRAGMA main.table_info({t})")
                                 if r[1] in bcols and r[1] not in skip)
                n = conn.execute(f"{verb} INTO main.{t}({cols}) SELECT {cols} FROM b.{t} {tail}").rowcount
                out[t] = n
                return n
            if "firewall" in sections:
                conn.execute("DELETE FROM logs")
                conn.execute("DELETE FROM firewalls")
                copy("firewalls")
                copy("logs")
            if "admin" in sections:
                if mode == "merge":
                    copy("servers", "INSERT OR IGNORE")
                    copy("events", "INSERT OR IGNORE", skip=("id",))
                    copy("fw_admin", skip=("id",), tail="AS x WHERE NOT EXISTS (SELECT 1 FROM main.fw_admin a "
                         "WHERE a.fw_ip = x.fw_ip AND a.ts = x.ts AND coalesce(a.raw, '') = coalesce(x.raw, ''))")
                else:
                    for t in ("events", "fw_admin", "servers"):
                        conn.execute(f"DELETE FROM main.{t}")
                    for t in ("servers", "events", "fw_admin"):
                        copy(t)
                if "sqlite_sequence" in have:
                    r = conn.execute("SELECT seq FROM b.sqlite_sequence WHERE name='servers'").fetchone()
                    if r:
                        conn.execute("UPDATE main.sqlite_sequence SET seq = max(seq, ?) WHERE name='servers'", (r[0],))
                conn.execute("UPDATE servers SET total = (SELECT count(*) FROM events WHERE srv_id = servers.id)")
            if "config" in sections:
                names = {}
                repos = []
                if "backup_repos" in have:
                    for r in conn.execute("SELECT * FROM b.backup_repos").fetchall():
                        names[r["id"]] = r["name"]
                        repos.append({"name": r["name"], "type": r["type"], "config": r["config"]})
                jobs = []
                if "backup_jobs" in have:
                    jobs = [dict(dict(r), repo=names.get(r["repo_id"]))
                            for r in conn.execute("SELECT * FROM b.backup_jobs").fetchall()]
                out["config"] = import_config(conn, repos, jobs)
                if "settings" in have:
                    conn.execute("INSERT OR REPLACE INTO main.settings(k, v) SELECT k, v FROM b.settings")
            conn.commit()
            box["out"] = out
        except Exception as e:
            log.exception("ripristino fallito")
            conn.rollback()
            box["err"] = f"ripristino non riuscito: {e}"
        finally:
            if attached:
                try:
                    conn.execute("DETACH DATABASE b")
                except sqlite3.Error:
                    pass
            if "firewall" in sections and not box["err"]:
                with self._lock:
                    self.deleting.clear()
                self._load_fw(conn)
            try:
                conn.execute("PRAGMA incremental_vacuum").fetchall()
                self._checkpoint(conn)
            except sqlite3.Error:
                pass
            box["ev"].set()

    def _command(self, conn, name, arg):
        try:
            if name == "ingest":
                self._ingest(conn, arg)
            elif name == "restore":
                self._restore(conn, arg)
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
        # Login degli amministratori ai firewall (registro accessi admin)
        days = admin_retention(conn)
        if days > 0:
            deleted += conn.execute("DELETE FROM fw_admin WHERE id IN (SELECT id FROM fw_admin WHERE ts < ? "
                                    "ORDER BY ts LIMIT ?)", (int((now - days * 86400) * 1000),
                                                              DEL_BLOCK * 10)).rowcount
            conn.commit()
        # Protezione disco pieno: elimina i log piu' vecchi finche' non c'e' spazio;
        # gli accessi dei server (pochi e piu' preziosi) solo quando i log sono finiti
        for _ in range(20):
            if shutil.disk_usage(DATA_DIR).free >= MIN_FREE_GB * 1024 ** 3:
                break
            n = (self._drop_oldest(conn, 50000) or self._drop_oldest(conn, 50000, EV_TBL)
                 or self._drop_oldest_admin(conn, 50000))
            conn.execute("PRAGMA incremental_vacuum").fetchall()
            self._checkpoint(conn)
            deleted += n
            if n == 0:
                break
            log.warning("spazio disco sotto %.1f GB: eliminati i %d log piu' vecchi", MIN_FREE_GB, n)
        if deleted:
            conn.execute("PRAGMA incremental_vacuum").fetchall()
            log.info("manutenzione: eliminati %d log", deleted)
        self._checkpoint(conn)

    def _checkpoint(self, conn):
        # durante un backup il TRUNCATE aspetterebbe la fine della lettura (fino al
        # busy_timeout) bloccando la scrittura dei log: basta un checkpoint passivo
        mode = "PASSIVE" if self.snapshot else "TRUNCATE"
        conn.execute(f"PRAGMA wal_checkpoint({mode})").fetchall()

    @staticmethod
    def _drop_oldest_admin(conn, n):
        d = conn.execute("DELETE FROM fw_admin WHERE id IN (SELECT id FROM fw_admin ORDER BY ts LIMIT ?)",
                         (n,)).rowcount
        conn.commit()
        return d


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
    c = store.connect(readonly=True)
    try:
        now = int(time.time() * 1000)
        admin, backup = admin_summary(c, now), backup_summary(c)
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
        "admin": admin, "backup": backup,
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

class HttpError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


# --------------------------------------------------------------------------
# Registro accessi amministratori (server Windows + login ai firewall)
# --------------------------------------------------------------------------
ADM_SRV = ("SELECT 'srv' AS dt, e.id, e.ts, CAST(e.srv_id AS TEXT) AS dev_id, s.name AS dev_name, e.kind, "
           "e.outcome, e.critical, e.elevated, e.account, e.domain, e.logon_type, e.auth, NULL AS method, "
           "e.src_ip, e.src_host, e.actor, e.target, e.reason, e.event_id, e.data AS raw "
           "FROM events e LEFT JOIN servers s ON s.id = e.srv_id")
ADM_FW = ("SELECT 'fw' AS dt, a.id, a.ts, a.fw_ip AS dev_id, coalesce(f.name, a.fw_name, a.fw_ip) AS dev_name, "
          "a.kind, a.outcome, 0 AS critical, 0 AS elevated, a.account, NULL AS domain, NULL AS logon_type, "
          "NULL AS auth, a.method, a.src_ip, NULL AS src_host, NULL AS actor, NULL AS target, a.reason, "
          "NULL AS event_id, a.raw FROM fw_admin a LEFT JOIN firewalls f ON f.ip = a.fw_ip")


def _adm_where(p, dt):
    """Condizioni di un ramo (server o firewall) del registro; None = ramo escluso."""
    a = "e" if dt == "srv" else "a"
    where, args = [], []

    def add(name, sql, xs):
        neg = p[name].strip().startswith("!")
        where.append(f"NOT coalesce({sql}, 0)" if neg else sql)
        args.extend(xs)

    def val(name):
        return p[name].strip().lstrip("!").strip()

    dev = p.get("dev", "")
    if dev:
        if dev.startswith("srv-"):
            if dt != "srv":
                return None
            where.append("e.srv_id = ?"); args.append(_int(dev[4:], "dispositivo"))
        elif dev.startswith("fw-"):
            if dt != "fw":
                return None
            where.append("a.fw_ip = ?"); args.append(dev[3:])
        else:
            raise ValueError("dispositivo non valido")
    if p.get("from"):
        where.append(f"{a}.ts >= ?"); args.append(_int(p["from"], "da"))
    if p.get("to"):
        where.append(f"{a}.ts <= ?"); args.append(_int(p["to"], "a"))
    if p.get("bts") and p.get("bdt") and p.get("bid"):
        # pagina successiva: ordinamento (ts, dt, id) decrescente
        bts, bid, bdt = _int(p["bts"], "bts"), _int(p["bid"], "bid"), p["bdt"]
        if dt < bdt:
            where.append(f"{a}.ts <= ?"); args.append(bts)
        elif dt > bdt:
            where.append(f"{a}.ts < ?"); args.append(bts)
        else:
            where.append(f"({a}.ts < ? OR ({a}.ts = ? AND {a}.id < ?))"); args.extend([bts, bts, bid])
    if p.get("ip") and val("ip"):
        sql, xs = ip_condition((f"{a}.src_n",), val("ip"))
        add("ip", sql, xs)
    if p.get("user") and val("user"):
        add("user", f"({a}.account = ? COLLATE NOCASE)", [_split_acct(val("user"))[0] or val("user")])
    for name in ("kind", "outcome"):
        if p.get(name) and val(name):
            add(name, f"({a}.{name} = ?)", [val(name)])
    if p.get("q") and val("q"):
        q = val("q").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        text = ("coalesce(e.account,'')||' '||coalesce(e.src_host,'')||' '||coalesce(e.actor,'')||' '||"
                "coalesce(e.target,'')||' '||coalesce(e.reason,'')||' '||coalesce(e.data,'')") if dt == "srv" else \
               ("coalesce(a.account,'')||' '||coalesce(a.method,'')||' '||coalesce(a.reason,'')||' '||"
                "coalesce(a.raw,'')")
        add("q", f"({text} LIKE ? ESCAPE '\\')", [f"%{q}%"])
    return where, args


def admin_query(p, limit):
    parts, args = [], []
    for dt, base in (("srv", ADM_SRV), ("fw", ADM_FW)):
        w = _adm_where(p, dt)
        if w is None:
            continue
        where, a = w
        al = "e" if dt == "srv" else "a"
        parts.append(f"SELECT * FROM ({base}{' WHERE ' + ' AND '.join(where) if where else ''} "
                     f"ORDER BY {al}.ts DESC, {al}.id DESC LIMIT {int(limit)})")
        args += a
    return (" UNION ALL ".join(parts) + f" ORDER BY ts DESC, dt DESC, id DESC LIMIT {int(limit)}"), args


def api_admin(p):
    limit = max(1, min(_int(p.get("limit", 200), "limit"), 1000))
    sql, args = admin_query(p, limit)
    c = store.connect(readonly=True)
    try:
        rows = c.execute(sql, args).fetchall()
    finally:
        c.close()
    return {"rows": [dict(r) for r in rows], "more": len(rows) == limit}


def api_admin_csv(p):
    sql, args = admin_query(p, 100000)
    cols = ["ts", "dispositivo", "tipo", "kind", "outcome", "critical", "account", "domain", "logon_type",
            "auth", "method", "src_ip", "src_host", "actor", "target", "reason", "event_id", "raw"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    c = store.connect(readonly=True)
    try:
        for r in c.execute(sql, args):
            row = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"] / 1000)), r["dev_name"],
                   "server" if r["dt"] == "srv" else "firewall"] + [r[k] for k in cols[3:]]
            w.writerow([("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
                        for v in row])
    finally:
        c.close()
    return buf.getvalue()


def api_admin_facets():
    c = store.connect(readonly=True)
    try:
        srv = [{"id": f"srv-{r[0]}", "name": r[1]} for r in
               c.execute("SELECT id, name FROM servers ORDER BY name COLLATE NOCASE")]
        fws = {r[0]: r[1] for r in c.execute("SELECT ip, name FROM firewalls WHERE ip NOT LIKE ?", (DELETED + "%",))}
        for ip, name in c.execute("SELECT fw_ip, max(fw_name) FROM fw_admin GROUP BY fw_ip"):
            fws.setdefault(ip, name or ip)
        users = set()
        for (u,) in c.execute("SELECT account FROM (SELECT account FROM events ORDER BY ts DESC LIMIT 5000) "
                              "UNION SELECT account FROM (SELECT account FROM fw_admin ORDER BY ts DESC LIMIT 5000)"):
            if u:
                users.add(u)
    finally:
        c.close()
    fw = sorted(({"id": f"fw-{ip}", "name": n, "ip": ip} for ip, n in fws.items()), key=lambda x: x["name"].lower())
    return {"servers": srv, "firewalls": fw, "user": sorted(users, key=str.lower)[:300]}


def admin_summary(c, now):
    day = now - 86400000
    fail = c.execute("SELECT (SELECT count(*) FROM events WHERE ts >= ? AND outcome = 'fail') + "
                     "(SELECT count(*) FROM fw_admin WHERE ts >= ? AND outcome = 'fail')", (day, day)).fetchone()[0]
    fw_total = c.execute("SELECT count(*) FROM fw_admin").fetchone()[0]
    v = get_setting(c, "fw_admin_retention_days")
    return {"fail_24h": fail, "fw_total": fw_total, "fw_retention_days": admin_retention(c),
            "fw_retention_set": None if v is None else int(v), "fw_retention_default": ADMIN_RETENTION_DAYS,
            "win_retention_days": WIN_RETENTION_DAYS}


def api_admin_settings(d):
    if "retention_days" not in d:
        raise ValueError("niente da modificare")
    v = _retention(d["retention_days"])
    c = store.connect()
    try:
        if v is None:
            c.execute("DELETE FROM settings WHERE k='fw_admin_retention_days'")
        else:
            c.execute("INSERT OR REPLACE INTO settings(k, v) VALUES('fw_admin_retention_days', ?)", (str(v),))
        c.commit()
    finally:
        c.close()
    return {"ok": True}

# --------------------------------------------------------------------------
# Backup e ripristino
# --------------------------------------------------------------------------
# Un backup e' un database SQLite con le sole tabelle scelte (piu' _meta e _files),
# compresso con gzip ed eventualmente cifrato con openssl (AES-256-CBC, PBKDF2):
#   openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -in X.fwbk | gunzip > X.db
# Accanto a ogni backup c'e' un .json con il riepilogo (manifest).
BK_TMP = os.path.join(DATA_DIR, "backup-tmp")
RESTORE_DIR = os.path.join(DATA_DIR, "restore")
BK_EXT = ".fwbk"
BK_FORMAT = 1
PBKDF2_ITER = "200000"
GB = 1024 ** 3
SECTIONS = {
    "admin": ("servers", "events", "fw_admin"),
    "firewall": ("firewalls", "logs"),
    "config": ("backup_repos", "backup_jobs", "settings"),
}
SECRETS = {"s3": ("secret_key",), "smb": ("password",)}
SMB_ERRORS = {
    "NT_STATUS_LOGON_FAILURE": "utente o password errati",
    "NT_STATUS_BAD_NETWORK_NAME": "condivisione inesistente",
    "NT_STATUS_ACCESS_DENIED": "accesso negato (permessi della condivisione o della cartella)",
    "NT_STATUS_OBJECT_NAME_NOT_FOUND": "file o cartella inesistente",
    "NT_STATUS_OBJECT_PATH_NOT_FOUND": "cartella inesistente",
    "NT_STATUS_HOST_UNREACHABLE": "server non raggiungibile",
    "NT_STATUS_IO_TIMEOUT": "server non raggiungibile (timeout)",
    "NT_STATUS_CONNECTION_REFUSED": "connessione rifiutata (porta 445 chiusa?)",
    "NT_STATUS_DISK_FULL": "spazio esaurito sulla condivisione",
    "NT_STATUS_UNSUCCESSFUL": "connessione non riuscita (nome del server?)",
    "NT_STATUS_OBJECT_NAME_COLLISION": "esiste gia' un file con lo stesso nome",
    "NT_STATUS_NO_SUCH_FILE": "file inesistente",
}


class BackupError(Exception):
    pass


def host_name():
    return re.sub(r"[^A-Za-z0-9-]+", "-", socket.gethostname().split(".")[0]).strip("-").lower() or "fwlog"


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "backup"


def _reserve():
    """Spazio da lasciare sempre libero sul disco dati durante backup e ripristini
    (sotto MIN_FREE_GB la manutenzione eliminerebbe i log)."""
    return int(MIN_FREE_GB * GB) + 512 * 1024 ** 2


def need_space(need, what):
    free = shutil.disk_usage(DATA_DIR).free
    if free - need < _reserve():
        raise BackupError(f"spazio insufficiente su {DATA_DIR} per {what}: servono circa "
                          f"{need / GB:.1f} GB oltre ai {_reserve() / GB:.1f} GB di riserva, liberi "
                          f"{free / GB:.1f} GB")


def space_guard():
    if shutil.disk_usage(DATA_DIR).free < _reserve():
        raise BackupError("spazio su disco quasi esaurito: operazione interrotta per non far eliminare i log")


def _ms_iso(ms):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000))


# ---- destinazioni ----
class LocalRepo:
    """Cartella locale: disco USB/aggiuntivo o NAS montato (NFS, CIFS) in fstab."""

    def __init__(self, cfg):
        self.path = cfg["path"]

    def where(self):
        return self.path

    def _check(self):
        if not os.path.isdir(self.path):
            raise BackupError(f"la cartella {self.path} non esiste o non e' raggiungibile (disco o NAS montato?)")
        st = os.stat(self.path)
        if st.st_dev == os.stat("/").st_dev:
            raise BackupError(f"{self.path} e' sul disco di sistema: il disco o il NAS non risulta montato")
        if st.st_dev == os.stat(DATA_DIR).st_dev:
            raise BackupError(f"{self.path} e' sullo stesso disco dei log: un backup qui non protegge da un guasto")
        if not os.access(self.path, os.W_OK):
            raise BackupError(f"l'utente fwlog non puo' scrivere in {self.path} (permessi o opzioni di mount)")

    def list(self):
        self._check()
        out = []
        for e in os.scandir(self.path):
            if e.is_file() and e.name.startswith("fwlog-"):
                st = e.stat()
                out.append({"name": e.name, "size": st.st_size, "mtime": int(st.st_mtime * 1000)})
        return out

    def put(self, local, name):
        self._check()
        dst = os.path.join(self.path, name)
        with open(local, "rb") as f, open(dst + ".part", "wb") as g:
            shutil.copyfileobj(f, g, 4 * 1024 * 1024)
            g.flush()
            os.fsync(g.fileno())
        os.replace(dst + ".part", dst)

    def get(self, name, local):
        shutil.copyfile(os.path.join(self.path, name), local)

    def delete(self, name):
        try:
            os.remove(os.path.join(self.path, name))
        except FileNotFoundError:
            pass

    def test(self):
        self._check()
        n = os.path.join(self.path, f".fwlog-test-{secrets.token_hex(4)}")
        with open(n, "wb") as f:
            f.write(b"ok")
        os.remove(n)
        du = shutil.disk_usage(self.path)
        return f"scrittura riuscita, spazio libero {du.free / GB:.1f} GB"


def s3_signature(method, canon_uri, canon_query, headers, payload_hash, access, secret, region, amz_date):
    """Firma AWS Signature V4 per S3. headers: dict con chiavi minuscole (tutte firmate).
    Restituisce il valore dell'header Authorization."""
    signed = sorted(headers)
    canon_headers = "".join(f"{k}:{' '.join(str(headers[k]).split())}\n" for k in signed)
    creq = "\n".join([method, canon_uri, canon_query, canon_headers, ";".join(signed), payload_hash])
    scope = f"{amz_date[:8]}/{region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ("AWS4" + secret).encode()
    for part in (amz_date[:8], region, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={';'.join(signed)}, Signature={sig}"


class S3Repo:
    """S3 o compatibile (AWS, Wasabi, Backblaze B2, MinIO, NAS con S3)."""
    PART = 16 * 1024 * 1024   # oltre: caricamento multipart a blocchi da 16 MB
    EMPTY = hashlib.sha256(b"").hexdigest()

    def __init__(self, cfg):
        self.cfg = cfg
        u = urlsplit(cfg["endpoint"])
        self.https = u.scheme == "https"
        self.host, self.port = u.hostname, u.port
        self.bucket, self.prefix = cfg["bucket"], cfg.get("prefix") or ""
        self.region = cfg.get("region") or "us-east-1"

    def where(self):
        return f"{self.cfg['endpoint']} · {self.bucket}/{self.prefix}"

    def _request(self, method, key=None, query=None, body=b"", out=None, extra=None):
        query = query or {}
        if self.cfg.get("path_style", True):
            host, path = self.host, "/" + self.bucket + ("/" + key if key is not None else "")
        else:
            host, path = f"{self.bucket}.{self.host}", "/" + (key or "")
        host_hdr = host if self.port is None else f"{host}:{self.port}"
        uri = quote(path, safe="/-_.~")
        cq = "&".join(f"{quote(k, safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in sorted(query.items()))
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        ph = hashlib.sha256(body).hexdigest() if body else self.EMPTY
        hdrs = {"host": host_hdr, "x-amz-content-sha256": ph, "x-amz-date": amz_date}
        hdrs.update(extra or {})
        hdrs["authorization"] = s3_signature(method, uri, cq, {k: v for k, v in hdrs.items()}, ph,
                                             self.cfg["access_key"], self.cfg["secret_key"], self.region, amz_date)
        if self.https:
            ctx = ssl.create_default_context()
            if not self.cfg.get("verify_tls", True):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, self.port, context=ctx, timeout=300)
        else:
            conn = http.client.HTTPConnection(host, self.port, timeout=300)
        try:
            try:
                conn.request(method, uri + ("?" + cq if cq else ""), body=body or None, headers=hdrs)
                resp = conn.getresponse()
            except ssl.SSLCertVerificationError as e:
                raise BackupError(f"S3: certificato non valido ({e.verify_message}); per un certificato "
                                  "autofirmato disattiva la verifica")
            except OSError as e:
                raise BackupError(f"S3: {host_hdr} non raggiungibile ({e})")
            if resp.status >= 300:
                data = resp.read()
                code = msg = ""
                try:
                    root = ET.fromstring(data)
                    code, msg = root.findtext("Code") or "", root.findtext("Message") or ""
                except ET.ParseError:
                    pass
                hint = {"NoSuchBucket": "bucket inesistente", "AccessDenied": "accesso negato",
                        "InvalidAccessKeyId": "access key non valida",
                        "SignatureDoesNotMatch": "secret key errata (o regione sbagliata)",
                        "AuthorizationHeaderMalformed": "regione sbagliata",
                        "PermanentRedirect": "regione o endpoint sbagliato"}.get(code, "")
                raise BackupError(f"S3: {resp.status} {code} {hint or msg}".strip())
            if out is not None:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                return resp, b""
            return resp, resp.read()
        finally:
            conn.close()

    def list(self):
        out, token = [], None
        while True:
            q = {"list-type": "2", "prefix": self.prefix + "fwlog-"}
            if token:
                q["continuation-token"] = token
            _, data = self._request("GET", None, q)
            root = ET.fromstring(data)
            for el_ in root.iter():
                el_.tag = el_.tag.split("}")[-1]
            for c in root.findall("Contents"):
                name = (c.findtext("Key") or "")[len(self.prefix):]
                if not name or "/" in name:
                    continue
                lm = c.findtext("LastModified") or ""
                try:
                    mt = int(datetime.datetime.strptime(lm[:19], "%Y-%m-%dT%H:%M:%S")
                             .replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
                except ValueError:
                    mt = None
                out.append({"name": name, "size": int(c.findtext("Size") or 0), "mtime": mt})
            if root.findtext("IsTruncated") != "true":
                return out
            token = root.findtext("NextContinuationToken")

    def put(self, local, name):
        key = self.prefix + name
        size = os.path.getsize(local)
        if size <= self.PART:
            with open(local, "rb") as f:
                self._request("PUT", key, body=f.read())
            return
        _, data = self._request("POST", key, {"uploads": ""})
        root = ET.fromstring(data)
        upload_id = next((e.text for e in root.iter() if e.tag.endswith("UploadId")), None)
        if not upload_id:
            raise BackupError("S3: avvio del caricamento multipart non riuscito")
        parts = []
        try:
            with open(local, "rb") as f:
                n = 0
                while True:
                    chunk = f.read(self.PART)
                    if not chunk:
                        break
                    n += 1
                    resp, _ = self._request("PUT", key, {"partNumber": str(n), "uploadId": upload_id}, body=chunk)
                    parts.append((n, resp.getheader("ETag")))
            xml = "<CompleteMultipartUpload>" + "".join(
                f"<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>" for n, etag in parts
            ) + "</CompleteMultipartUpload>"
            _, data = self._request("POST", key, {"uploadId": upload_id}, body=xml.encode())
            if b"<Error>" in data:   # S3 puo' rispondere 200 con un errore nel corpo
                raise BackupError("S3: completamento del caricamento non riuscito")
        except Exception:
            try:
                self._request("DELETE", key, {"uploadId": upload_id})
            except Exception:
                pass
            raise

    def get(self, name, local):
        with open(local, "wb") as f:
            self._request("GET", self.prefix + name, out=f)

    def delete(self, name):
        self._request("DELETE", self.prefix + name)

    def test(self):
        name = f".fwlog-test-{secrets.token_hex(4)}"
        self._request("PUT", self.prefix + name, body=b"ok")
        self._request("DELETE", self.prefix + name)
        n = len(self.list())
        return f"scrittura riuscita, {n} file di backup presenti"


class SmbRepo:
    """Condivisione SMB (Windows, NAS) tramite smbclient, senza montarla."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.folder = cfg.get("folder") or ""

    def where(self):
        return f"//{self.cfg['server']}/{self.cfg['share']}/{self.folder}".rstrip("/")

    def _run(self, cmds, timeout=None, ok_status=()):
        exe = shutil.which("smbclient")
        if not exe:
            raise BackupError("smbclient non installato: rieseguire install.sh (pacchetto samba-client "
                              "su Rocky, smbclient su Ubuntu)")
        args = [exe, f"//{self.cfg['server']}/{self.cfg['share']}"]
        auth = None
        if self.cfg.get("user"):
            fd, auth = tempfile.mkstemp(prefix="fwlog-smb-")
            with os.fdopen(fd, "w") as f:
                f.write(f"username = {self.cfg['user']}\npassword = {self.cfg.get('password', '')}\n")
                if self.cfg.get("domain"):
                    f.write(f"domain = {self.cfg['domain']}\n")
            args += ["-A", auth]
        else:
            args.append("-N")
        env = dict(os.environ, LC_ALL="C", HOME=tempfile.gettempdir())
        try:
            r = subprocess.run(args + ["-c", cmds], capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            raise BackupError("SMB: il server non risponde")
        finally:
            if auth:
                os.remove(auth)
        text = r.stdout + "\n" + r.stderr
        bad = [m for m in re.findall(r"NT_STATUS_\w+", text) if m not in ok_status]
        if bad or (r.returncode != 0 and not re.findall(r"NT_STATUS_\w+", text)):
            if bad:
                raise BackupError(f"SMB: {SMB_ERRORS.get(bad[0], bad[0])}")
            raise BackupError("SMB: " + (r.stderr.strip().splitlines() or ["errore di smbclient"])[-1][:200])
        return r.stdout

    def _p(self, name):
        # percorsi completi in ogni comando: con "cd" seguito da altri comandi, un cd
        # fallito farebbe scrivere nella radice della condivisione
        return f"{self.folder}/{name}" if self.folder else name

    def _mkdirs(self):
        path = ""
        for part in [x for x in self.folder.split("/") if x]:
            path = f"{path}/{part}" if path else part
            self._run(f'mkdir "{path}"', 120, ok_status=("NT_STATUS_OBJECT_NAME_COLLISION",))

    def list(self):
        out = []
        text = self._run(f'ls "{self._p("fwlog-*")}"', 120, ok_status=("NT_STATUS_NO_SUCH_FILE",))
        for line in text.splitlines():
            m = re.match(r"^  (\S+)\s+[A-Z]*\s+(\d+)\s+(\w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d \d{4})$", line)
            if m and m.group(1).startswith("fwlog-"):
                try:
                    mt = int(time.mktime(time.strptime(m.group(3), "%a %b %d %H:%M:%S %Y")) * 1000)
                except ValueError:
                    mt = None
                out.append({"name": m.group(1), "size": int(m.group(2)), "mtime": mt})
        return out

    def put(self, local, name):
        self._mkdirs()
        part, dst = self._p(name + ".part"), self._p(name)
        try:
            self._run(f'put "{local}" "{part}"; rename "{part}" "{dst}"')
        except BackupError:
            try:
                self._run(f'del "{part}"', 120, ok_status=("NT_STATUS_NO_SUCH_FILE", "NT_STATUS_OBJECT_NAME_NOT_FOUND"))
            except BackupError:
                pass
            raise

    def get(self, name, local):
        self._run(f'get "{self._p(name)}" "{local}"')

    def delete(self, name):
        self._run(f'del "{self._p(name)}"', 120, ok_status=("NT_STATUS_NO_SUCH_FILE",
                                                          "NT_STATUS_OBJECT_NAME_NOT_FOUND"))

    def test(self):
        self._mkdirs()
        fd, tmp = tempfile.mkstemp(prefix="fwlog-test-")
        os.write(fd, b"ok")
        os.close(fd)
        name = self._p(f".fwlog-test-{secrets.token_hex(4)}")
        try:
            self._run(f'put "{tmp}" "{name}"; del "{name}"', 120)
        finally:
            os.remove(tmp)
        return f"scrittura riuscita, {len(self.list())} file di backup presenti"


REPO_TYPES = {"local": LocalRepo, "s3": S3Repo, "smb": SmbRepo}


def make_repo(rtype, cfg):
    return REPO_TYPES[rtype](cfg)


def _str(d, k, maxlen=200, required=False, what=None):
    v = d.get(k)
    v = "" if v is None else str(v).strip()
    if "\n" in v or "\r" in v or len(v) > maxlen:
        raise ValueError(f"{what or k}: valore non valido")
    if required and not v:
        raise ValueError(f"indica {what or k}")
    return v


def clean_repo(d, old_cfg=None):
    """Valida nome, tipo e parametri di una destinazione; i segreti vuoti restano invariati."""
    name = _str(d, "name", 80, True, "il nome della destinazione")
    rtype = d.get("type")
    if rtype not in REPO_TYPES:
        raise ValueError("tipo di destinazione non valido")
    c = d.get("config") or {}
    if not isinstance(c, dict):
        raise ValueError("configurazione non valida")
    old = old_cfg or {}
    if rtype == "local":
        path = _str(c, "path", 400, True, "la cartella")
        if not path.startswith("/") or "/../" in path + "/" or '"' in path:
            raise ValueError("la cartella deve essere un percorso assoluto, es. /mnt/nas-backup")
        cfg = {"path": os.path.normpath(path)}
    elif rtype == "s3":
        region = _str(c, "region", 40) or "us-east-1"
        endpoint = _str(c, "endpoint", 300).rstrip("/") or f"https://s3.{region}.amazonaws.com"
        u = urlsplit(endpoint)
        if u.scheme not in ("http", "https") or not u.hostname or u.path not in ("", "/"):
            raise ValueError("endpoint non valido, es. https://s3.eu-south-1.amazonaws.com")
        bucket = _str(c, "bucket", 63, True, "il bucket")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-_]{1,62}", bucket):
            raise ValueError("nome del bucket non valido")
        prefix = _str(c, "prefix", 200).strip("/")
        if prefix and not re.fullmatch(r"[A-Za-z0-9!\-_.*'()/ ]+", prefix):
            raise ValueError("cartella (prefisso) non valida")
        cfg = {"endpoint": endpoint, "region": region, "bucket": bucket, "prefix": prefix + "/" if prefix else "",
               "access_key": _str(c, "access_key", 200, True, "l'access key"),
               "secret_key": _str(c, "secret_key", 200) or old.get("secret_key", ""),
               "path_style": c.get("path_style") is not False, "verify_tls": c.get("verify_tls") is not False}
        if not cfg["secret_key"]:
            raise ValueError("indica la secret key")
    else:
        server = _str(c, "server", 200, True, "il server")
        if not re.fullmatch(r"[A-Za-z0-9.\-_:\[\]]+", server):
            raise ValueError("nome o indirizzo del server non valido")
        share = _str(c, "share", 80, True, "la condivisione")
        folder = _str(c, "folder", 200).replace("\\", "/").strip("/")
        user = _str(c, "user", 100)
        domain = _str(c, "domain", 100)
        if "\\" in user and not domain:     # DOMINIO\utente
            domain, user = user.split("\\", 1)
        for v, what in ((share, "condivisione"), (user, "utente"), (domain, "dominio")):
            if re.search(r'["\x00-\x1f;/\\]', v):
                raise ValueError(f"{what}: caratteri non ammessi")
        if re.search(r'["\x00-\x1f;]|(^|/)\.\.(/|$)', folder):
            raise ValueError("cartella: caratteri non ammessi")
        cfg = {"server": server, "share": share, "folder": folder, "user": user, "domain": domain,
               "password": _str(c, "password", 200) or (old.get("password", "") if user == old.get("user") else "")}
    return name, rtype, cfg


def public_repo(r):
    cfg = json.loads(r["config"])
    out = {"id": r["id"], "name": r["name"], "type": r["type"], "config": dict(cfg)}
    for k in SECRETS.get(r["type"], ()):
        out["config"][k] = ""
        out["config"]["has_" + k] = bool(cfg.get(k))
    try:
        out["where"] = make_repo(r["type"], cfg).where()
    except Exception:
        out["where"] = ""
    return out


# ---- pianificazione ----
WEEKDAYS = ("lun", "mar", "mer", "gio", "ven", "sab", "dom")


def clean_schedule(s):
    if not isinstance(s, dict):
        raise ValueError("pianificazione non valida")
    freq = s.get("freq")
    if freq not in ("daily", "weekly", "monthly", "hours", "manual"):
        raise ValueError("frequenza non valida")
    out = {"freq": freq}
    t = str(s.get("time") or "02:00")
    m = re.fullmatch(r"(\d{1,2}):(\d\d)", t)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise ValueError("ora non valida (formato HH:MM)")
    out["time"] = f"{int(m.group(1)):02d}:{m.group(2)}"
    if freq == "weekly":
        days = sorted({int(x) for x in s.get("days") or [] if str(x).isdigit() and 1 <= int(x) <= 7})
        if not days:
            raise ValueError("scegli almeno un giorno della settimana")
        out["days"] = days
    if freq == "monthly":
        out["mday"] = _int(s.get("mday", 1), "giorno del mese")
        if not 1 <= out["mday"] <= 28:
            raise ValueError("il giorno del mese deve essere tra 1 e 28")
    if freq == "hours":
        out["every"] = _int(s.get("every", 6), "ore")
        if not 1 <= out["every"] <= 24:
            raise ValueError("l'intervallo deve essere tra 1 e 24 ore")
    return out


def next_run(s, now_ms):
    """Prossima esecuzione (ms) dopo now_ms secondo la pianificazione, ora locale."""
    freq = s.get("freq")
    if freq == "manual":
        return None
    now = datetime.datetime.fromtimestamp(now_ms / 1000)
    hh, mm = (int(x) for x in s.get("time", "02:00").split(":"))
    day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if freq == "hours":
        # orari fissi ogni giorno: dall'ora scelta, ogni N ore (es. 02:30, 08:30, 14:30, 20:30)
        every = s.get("every", 6) * 60
        start = hh * 60 + mm
        mins = sorted({(start + k * every) % 1440 for k in range(-(-1440 // every))})
        for add in (0, 1):
            for m in mins:
                t = day0 + datetime.timedelta(days=add, minutes=m)
                if t > now:
                    return int(t.timestamp() * 1000)
        return None
    for add in range(0, 400):
        d = day0 + datetime.timedelta(days=add)
        if freq == "weekly" and d.isoweekday() not in s.get("days", []):
            continue
        if freq == "monthly" and d.day != s.get("mday", 1):
            continue
        t = d.replace(hour=hh, minute=mm)
        if t > now:
            return int(t.timestamp() * 1000)
    return None


def clean_job(d, conn, old=None):
    name = _str(d, "name", 80, True, "il nome del job")
    try:
        repo_id = int(d.get("repo_id"))
    except (TypeError, ValueError):
        raise ValueError("scegli la destinazione")
    if not conn.execute("SELECT 1 FROM backup_repos WHERE id=?", (repo_id,)).fetchone():
        raise ValueError("destinazione inesistente")
    contents = d.get("contents")
    if not isinstance(contents, list) or not contents or any(x not in ("admin", "firewall") for x in contents):
        raise ValueError("scegli cosa salvare: accessi amministratori e/o log dei firewall")
    keep = _int(d.get("keep", 7), "copie da conservare")
    if not 0 <= keep <= 10000:
        raise ValueError("copie da conservare: da 0 (tutte) a 10000")
    if d.get("encrypt") is False:
        password = None
    else:
        password = _str(d, "password", 200) or (old["password"] if old else None)
        if d.get("encrypt") and not password:
            raise ValueError("indica la password di cifratura")
        if password is not None and len(password) < 8:
            raise ValueError("la password di cifratura deve avere almeno 8 caratteri")
    return {"name": name, "repo_id": repo_id, "contents": json.dumps(sorted(set(contents))),
            "schedule": json.dumps(clean_schedule(d.get("schedule") or {})), "keep": keep,
            "password": password, "enabled": 0 if d.get("enabled") is False else 1}


def public_job(r):
    j = dict(r)
    j["encrypted"] = bool(j.pop("password"))
    j["contents"] = json.loads(j["contents"])
    j["schedule"] = json.loads(j["schedule"])
    return j


def import_config(conn, repos, jobs):
    """Aggiunge o aggiorna per nome destinazioni e job (configurazione esportata o
    contenuta in un backup). repos: [{name, type, config}], jobs: [{..., repo: nome}]."""
    nr = nj = 0
    ids = {}
    for r in repos:
        cfg = r.get("config")
        if isinstance(cfg, str):
            cfg = json.loads(cfg)
        old = conn.execute("SELECT id, type, config FROM backup_repos WHERE name=?", (r.get("name"),)).fetchone()
        old_cfg = json.loads(old["config"]) if old and old["type"] == r.get("type") else None
        name, rtype, cfg = clean_repo({"name": r.get("name"), "type": r.get("type"), "config": cfg}, old_cfg)
        if old:
            conn.execute("UPDATE backup_repos SET type=?, config=? WHERE id=?", (rtype, json.dumps(cfg), old["id"]))
            ids[name] = old["id"]
        else:
            ids[name] = conn.execute("INSERT INTO backup_repos(name, type, config, created) VALUES(?,?,?,?)",
                                     (name, rtype, json.dumps(cfg), int(time.time() * 1000))).lastrowid
        nr += 1
    for j in jobs:
        repo = j.get("repo")
        rid = ids.get(repo)
        if rid is None:
            row = conn.execute("SELECT id FROM backup_repos WHERE name=?", (repo,)).fetchone()
            rid = row[0] if row else None
        old = conn.execute("SELECT * FROM backup_jobs WHERE name=?", (j.get("name"),)).fetchone()
        sched = j.get("schedule")
        contents = j.get("contents")
        d = dict(j, repo_id=rid, schedule=json.loads(sched) if isinstance(sched, str) else sched,
                 contents=json.loads(contents) if isinstance(contents, str) else contents,
                 enabled=bool(j.get("enabled", True)))
        d["encrypt"] = bool(j.get("password")) or None
        v = clean_job(d, conn, old)
        nxt = next_run(json.loads(v["schedule"]), int(time.time() * 1000)) if v["enabled"] else None
        if old:
            conn.execute("UPDATE backup_jobs SET repo_id=?, contents=?, schedule=?, keep=?, password=?, enabled=?, "
                         "next_run=? WHERE id=?", (v["repo_id"], v["contents"], v["schedule"], v["keep"],
                                                   v["password"], v["enabled"], nxt, old["id"]))
        else:
            conn.execute("INSERT INTO backup_jobs(name, repo_id, contents, schedule, keep, password, enabled, "
                         "created, next_run) VALUES(?,?,?,?,?,?,?,?,?)",
                         (v["name"], v["repo_id"], v["contents"], v["schedule"], v["keep"], v["password"],
                          v["enabled"], int(time.time() * 1000), nxt))
        nj += 1
    return {"repos": nr, "jobs": nj}


def export_config(conn, with_secrets=True):
    repos, names = [], {}
    for r in conn.execute("SELECT * FROM backup_repos ORDER BY name"):
        cfg = json.loads(r["config"])
        if not with_secrets:
            for k in SECRETS.get(r["type"], ()):
                cfg.pop(k, None)
        repos.append({"name": r["name"], "type": r["type"], "config": cfg})
        names[r["id"]] = r["name"]
    jobs = []
    for r in conn.execute("SELECT * FROM backup_jobs ORDER BY name"):
        j = {"name": r["name"], "repo": names.get(r["repo_id"]), "contents": json.loads(r["contents"]),
             "schedule": json.loads(r["schedule"]), "keep": r["keep"], "enabled": bool(r["enabled"])}
        if with_secrets and r["password"]:
            j["password"] = r["password"]
        jobs.append(j)
    return {"fwlog": "backup-config", "version": 1, "exported": _ms_iso(time.time() * 1000),
            "host": host_name(), "secrets": with_secrets, "repos": repos, "jobs": jobs}


# ---- creazione, compressione e cifratura ----
def make_snapshot(dst, contents, label):
    """Copia coerente (una sola transazione di lettura) delle tabelle scelte in un
    nuovo database `dst`, che e' a sua volta un database fwlog valido."""
    tables = list(SECTIONS["config"])
    for c in contents:
        tables += SECTIONS[c]
    for sfx in ("", "-journal"):
        if os.path.exists(dst + sfx):
            os.remove(dst + sfx)
    c = sqlite3.connect(dst, isolation_level=None, timeout=30)
    try:
        c.execute("PRAGMA auto_vacuum=INCREMENTAL")
        c.execute("PRAGMA journal_mode=OFF")
        c.execute("PRAGMA synchronous=OFF")
        c.execute("ATTACH DATABASE ? AS src", (DB_PATH,))
        c.execute("PRAGMA src.busy_timeout=30000")
        n = [0]

        def progress():
            n[0] += 1
            try:
                space_guard()
            except BackupError:
                return 1
            return 0
        c.set_progress_handler(progress, 500000)
        c.execute("BEGIN")
        counts, ranges = {}, {}
        for t in tables:
            row = c.execute("SELECT sql FROM src.sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()
            if not row:
                continue
            c.execute(row[0])
            counts[t] = c.execute(f"INSERT INTO main.{t} SELECT * FROM src.{t}").rowcount
        for t in ("events", "fw_admin", "logs"):
            if t in counts and counts[t]:
                ranges[t] = list(c.execute(f"SELECT min(ts), max(ts) FROM src.{t}").fetchone())
        seq = c.execute("SELECT seq FROM src.sqlite_sequence WHERE name='servers'").fetchone() \
            if "servers" in counts else None
        if seq:
            c.execute("UPDATE main.sqlite_sequence SET seq=? WHERE name='servers'", seq)
        c.execute("CREATE TABLE _files(name TEXT PRIMARY KEY, data BLOB)")
        for name, path in (("tls.crt", TLS_CERT), ("tls.key", TLS_KEY), ("fwlog.env", os.path.join(ETC_DIR, "fwlog.env"))):
            try:
                with open(path, "rb") as f:
                    c.execute("INSERT INTO _files VALUES(?,?)", (name, f.read()))
            except (OSError, TypeError):
                pass
        meta = {"format": BK_FORMAT, "app": "fwlog", "created": int(time.time() * 1000), "host": host_name(),
                "job": label, "contents": sorted(set(contents) | {"config"}), "counts": counts,
                "ranges": ranges, "tls_pin": TLS_PIN}
        c.execute("CREATE TABLE _meta(k TEXT PRIMARY KEY, v TEXT)")
        c.execute("INSERT INTO _meta VALUES('meta', ?)", (json.dumps(meta),))
        c.execute("COMMIT")
    except sqlite3.OperationalError as e:
        if "interrupt" in str(e):
            raise BackupError("spazio su disco quasi esaurito: backup interrotto per non far eliminare i log")
        raise
    finally:
        c.close()
    return meta


def _openssl(password, src=None):
    """openssl enc: cifra da stdin, oppure (src) decifra il file. La password passa
    da una pipe, non dalla riga di comando."""
    if not shutil.which("openssl"):
        raise BackupError("openssl non installato")
    r, w = os.pipe()
    os.write(w, password.encode() + b"\n")
    os.close(w)
    args = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", PBKDF2_ITER, "-md", "sha256",
            "-pass", f"fd:{r}"]
    args += ["-d", "-in", src] if src else ["-salt"]
    try:
        return subprocess.Popen(args, stdin=None if src else subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(r,))
    finally:
        os.close(r)


class _HashOut:
    def __init__(self, f):
        self.f, self.h, self.size = f, hashlib.sha256(), 0

    def write(self, b):
        self.f.write(b)
        self.h.update(b)
        self.size += len(b)
        return len(b)

    def flush(self):
        self.f.flush()


def pack(src, dst, password=None, guard=True):
    """gzip di `src` (+ AES-256 con openssl se c'e' una password) in `dst`.
    Restituisce (dimensione, sha256)."""
    with open(dst, "wb") as raw:
        out = _HashOut(raw)
        proc = pump = None
        if password:
            proc = _openssl(password)

            def _pump():
                while True:
                    b = proc.stdout.read(1024 * 1024)
                    if not b:
                        break
                    out.write(b)
            pump = threading.Thread(target=_pump, daemon=True)
            pump.start()
            sink = proc.stdin
        else:
            sink = out
        try:
            with open(src, "rb") as f, gzip.GzipFile(filename="fwlog.db", mode="wb", fileobj=sink,
                                                     compresslevel=6, mtime=0) as gz:
                n = 0
                while True:
                    b = f.read(1024 * 1024)
                    if not b:
                        break
                    gz.write(b)
                    n += 1
                    if guard and n % 64 == 0:
                        space_guard()
        finally:
            if proc:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
                pump.join()
                rc = proc.wait()
                if rc:
                    raise BackupError("cifratura non riuscita: " + proc.stderr.read().decode(errors="replace")[:200])
    return out.size, out.h.hexdigest()


def is_encrypted(path):
    with open(path, "rb") as f:
        head = f.read(8)
    if head == b"Salted__":
        return True
    if head[:2] == b"\x1f\x8b":
        return False
    raise BackupError("il file non e' un backup di fwlog")


def unpack(src, dst, password=None, guard=True):
    """Decifra e decomprime un backup in `dst` (database SQLite); restituisce il riepilogo."""
    enc = is_encrypted(src)
    if enc and not password:
        raise BackupError("il backup e' cifrato: serve la password")
    proc = _openssl(password, src) if enc else None
    fin = proc.stdout if proc else open(src, "rb")
    ok = False
    try:
        with gzip.GzipFile(fileobj=fin, mode="rb") as gz, open(dst, "wb") as f:
            n = 0
            while True:
                b = gz.read(1024 * 1024)
                if not b:
                    break
                f.write(b)
                n += 1
                if guard and n % 64 == 0:
                    space_guard()
        ok = True
    except (OSError, EOFError, zlib.error):
        raise BackupError("password errata o file danneggiato" if enc else "file danneggiato o incompleto")
    finally:
        fin.close()
        if proc and proc.wait() and ok:
            ok = False
            raise BackupError("password errata o file danneggiato")
        if not ok and os.path.exists(dst):
            os.remove(dst)
    return backup_meta(dst)


def backup_meta(db):
    """Riepilogo di un backup decompresso; errore se non e' un backup fwlog."""
    try:
        c = sqlite3.connect(f"file:{quote(db)}?mode=ro", uri=True)
        try:
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            meta = json.loads(c.execute("SELECT v FROM _meta WHERE k='meta'").fetchone()[0])
            files = [r[0] for r in c.execute("SELECT name FROM _files")] if "_files" in tables else []
        finally:
            c.close()
    except (sqlite3.DatabaseError, TypeError, ValueError):
        raise BackupError("il file non e' un backup di fwlog valido")
    if meta.get("app") != "fwlog":
        raise BackupError("il file non e' un backup di fwlog")
    if meta.get("format", 0) > BK_FORMAT:
        raise BackupError("backup creato da una versione piu' recente di fwlog: aggiornare prima fwlog")
    meta["tables"] = sorted(tables)
    meta["files"] = files
    meta["db_size"] = os.path.getsize(db)
    return meta


# ---- esecuzione (un'operazione alla volta) ----
class Backups:
    def __init__(self):
        self.lock = threading.Lock()
        self.task = None        # operazione in corso: {kind, label, phase, started}
        self.stage = {}         # ripristino in preparazione: {src, origin, db, meta, encrypted}
        self.last = None        # esito dell'ultima operazione avviata dalla dashboard

    def busy(self):
        return self.task is not None

    def start(self, kind, label, fn, *args):
        with self.lock:
            if self.task:
                raise HttpError(409, f"operazione in corso: {self.task['label']}")
            self.task = {"kind": kind, "label": label, "phase": "avvio", "started": int(time.time() * 1000)}

        def run():
            try:
                # priorita' bassa (vale per questo thread e per openssl/smbclient che avvia):
                # la ricezione dei log non deve rallentare durante un backup
                os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 15)
            except (OSError, AttributeError):
                pass
            try:
                fn(*args)
                self.last = {"kind": kind, "label": label, "ok": True, "at": int(time.time() * 1000)}
            except Exception as e:
                if not isinstance(e, (BackupError, ValueError)):
                    log.exception("%s fallito", label)
                self.last = {"kind": kind, "label": label, "ok": False, "msg": str(e) or e.__class__.__name__,
                             "at": int(time.time() * 1000)}
            finally:
                self.task = None
        threading.Thread(target=run, name="backup", daemon=True).start()

    def phase(self, text):
        if self.task:
            self.task["phase"] = text

    # ---- job di backup ----
    def run_job(self, job_id):
        c = store.connect()
        started = int(time.time() * 1000)
        try:
            job = c.execute("SELECT * FROM backup_jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                raise BackupError("job inesistente")
            repo_row = c.execute("SELECT * FROM backup_repos WHERE id=?", (job["repo_id"],)).fetchone()
            run_id = c.execute("INSERT INTO backup_runs(job_id, job_name, kind, started, status, repo) "
                               "VALUES(?,?,?,?,?,?)", (job_id, job["name"], "backup", started, "running",
                                                       repo_row["name"] if repo_row else None)).lastrowid
            c.commit()
        finally:
            c.close()
        name = f"fwlog-{host_name()}-{slug(job['name'])}-{time.strftime('%Y%m%d-%H%M%S')}{BK_EXT}"
        tmp_db, tmp_out = os.path.join(BK_TMP, name + ".db"), os.path.join(BK_TMP, name)
        status, msg, size = "error", None, None
        try:
            if not repo_row:
                raise BackupError("la destinazione del job non esiste piu'")
            repo = make_repo(repo_row["type"], json.loads(repo_row["config"]))
            contents = json.loads(job["contents"])
            os.makedirs(BK_TMP, exist_ok=True)
            db_size = sum(os.path.getsize(DB_PATH + s) for s in ("", "-wal") if os.path.exists(DB_PATH + s))
            # stima: copia delle tabelle (senza indici) + file compresso
            est = db_size if "firewall" in contents else min(db_size, 64 * 1024 ** 2 + db_size // 4)
            need_space(int(est * 1.3), "il backup")
            self.phase("copia dei dati")
            store.snapshot += 1
            try:
                meta = make_snapshot(tmp_db, contents, job["name"])
            finally:
                store.snapshot -= 1
            self.phase("compressione e cifratura" if job["password"] else "compressione")
            size, sha = pack(tmp_db, tmp_out, job["password"])
            meta.update(file=name, size=size, sha256=sha, encrypted=bool(job["password"]),
                        db_size=os.path.getsize(tmp_db))
            os.remove(tmp_db)
            self.phase(f"invio a «{repo_row['name']}»")
            repo.put(tmp_out, name)
            mf = os.path.join(BK_TMP, name[:-len(BK_EXT)] + ".json")
            with open(mf, "w") as f:
                json.dump(meta, f, indent=1)
            try:
                repo.put(mf, os.path.basename(mf))
            finally:
                os.remove(mf)
            if job["keep"]:
                self.phase("eliminazione delle copie vecchie")
                prefix = f"fwlog-{host_name()}-{slug(job['name'])}-"
                old = sorted((f["name"] for f in repo.list()
                              if f["name"].startswith(prefix) and f["name"].endswith(BK_EXT)), reverse=True)
                for n in old[job["keep"]:]:
                    repo.delete(n)
                    repo.delete(n[:-len(BK_EXT)] + ".json")
            status, msg = "ok", name
            log.info("backup %s completato: %s (%d byte)", job["name"], name, size)
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            if not isinstance(e, BackupError):
                log.exception("backup %s fallito", job["name"])
            else:
                log.error("backup %s fallito: %s", job["name"], msg)
        finally:
            for p in (tmp_db, tmp_out):
                if os.path.exists(p):
                    os.remove(p)
        now = int(time.time() * 1000)
        c = store.connect()
        try:
            c.execute("UPDATE backup_runs SET ended=?, status=?, msg=?, file=?, size=? WHERE id=?",
                      (now, status, msg, name if status == "ok" else None, size, run_id))
            c.execute("UPDATE backup_jobs SET last_run=?, last_status=?, last_msg=? WHERE id=?",
                      (now, status, msg, job_id))
            c.execute("DELETE FROM backup_runs WHERE id NOT IN (SELECT id FROM backup_runs ORDER BY id DESC LIMIT 500)")
            c.commit()
        finally:
            c.close()
        if status != "ok":
            raise BackupError(msg)

    def scheduler(self):
        """Avvia i job pianificati (uno alla volta); un job saltato a macchina spenta
        parte al riavvio."""
        time.sleep(20)
        while True:
            try:
                if not self.task:
                    now = int(time.time() * 1000)
                    c = store.connect()
                    try:
                        due = c.execute("SELECT id, name, schedule FROM backup_jobs WHERE enabled=1 AND "
                                        "next_run IS NOT NULL AND next_run <= ? ORDER BY next_run LIMIT 1",
                                        (now,)).fetchone()
                        if due:
                            c.execute("UPDATE backup_jobs SET next_run=? WHERE id=?",
                                      (next_run(json.loads(due["schedule"]), now + 60000), due["id"]))
                            c.commit()
                    finally:
                        c.close()
                    if due:
                        try:
                            self.start("backup", f"backup «{due['name']}»", self.run_job, due["id"])
                        except HttpError:
                            pass
            except Exception:
                log.exception("errore nella pianificazione dei backup")
            time.sleep(15)

    # ---- ripristino ----
    def clear_stage(self):
        for k in ("src", "db"):
            p = self.stage.get(k)
            if p and os.path.exists(p):
                os.remove(p)
        self.stage = {}

    def prepare(self, repo_id, name, password):
        """Scarica (se serve), decifra e decomprime il backup da ripristinare."""
        if repo_id is not None:
            self.clear_stage()
            c = store.connect(readonly=True)
            try:
                r = c.execute("SELECT * FROM backup_repos WHERE id=?", (repo_id,)).fetchone()
            finally:
                c.close()
            if not r:
                raise BackupError("destinazione inesistente")
            repo = make_repo(r["type"], json.loads(r["config"]))
            files = {f["name"]: f for f in repo.list()}
            if name not in files:
                raise BackupError("backup non trovato nella destinazione")
            need_space(files[name]["size"] * 6, "scaricare e decomprimere il backup")
            os.makedirs(RESTORE_DIR, exist_ok=True)
            src = os.path.join(RESTORE_DIR, "download" + BK_EXT)
            self.phase(f"download da «{r['name']}»")
            repo.get(name, src)
            self.stage = {"src": src, "origin": f"{name} da «{r['name']}»"}
        if not self.stage.get("src"):
            raise BackupError("nessun backup da ripristinare: caricalo o sceglilo da una destinazione")
        if self.stage.get("db") and os.path.exists(self.stage["db"]):
            os.remove(self.stage["db"])
        self.stage.pop("meta", None)
        db = os.path.join(RESTORE_DIR, "restore.db")
        need_space(os.path.getsize(self.stage["src"]) * 5, "decomprimere il backup")
        self.stage["encrypted"] = is_encrypted(self.stage["src"])
        self.phase("decifratura e decompressione" if self.stage["encrypted"] else "decompressione")
        self.stage["meta"] = unpack(self.stage["src"], db, password)
        self.stage["db"] = db

    def restore(self, sections, mode):
        meta = self.stage.get("meta")
        if not meta:
            raise BackupError("prepara prima il backup da ripristinare")
        c = store.connect(readonly=True)
        try:
            if "firewall" in sections and c.execute("SELECT 1 FROM firewalls WHERE ip LIKE ?",
                                                    (DELETED + "%",)).fetchone():
                raise BackupError("eliminazione di un firewall in corso: riprova tra qualche minuto")
            if "admin" in sections and c.execute("SELECT 1 FROM events WHERE srv_id NOT IN "
                                                 "(SELECT id FROM servers) LIMIT 1").fetchone():
                raise BackupError("eliminazione di un server in corso: riprova tra qualche minuto")
        finally:
            c.close()
        need_space(int(meta["db_size"] * 1.5), "il ripristino")
        self.phase("ripristino nel database (la ricezione dei log riprende alla fine)")
        box = {"ev": threading.Event(), "err": None, "out": None}
        store.command("restore", (self.stage["db"], sections, mode, box))
        box["ev"].wait()
        started = self.task["started"] if self.task else int(time.time() * 1000)
        c = store.connect()
        try:
            c.execute("INSERT INTO backup_runs(job_name, kind, started, ended, status, msg, file) VALUES(?,?,?,?,?,?,?)",
                      ("ripristino", "restore", started, int(time.time() * 1000), "error" if box["err"] else "ok",
                       box["err"] or ", ".join(sections), meta.get("file") or self.stage.get("origin")))
            c.commit()
        finally:
            c.close()
        if box["err"]:
            raise BackupError(box["err"])
        log.info("ripristino completato (%s) da %s", ", ".join(sections), self.stage.get("origin"))
        self.clear_stage()


bk = Backups()


def api_backup():
    c = store.connect(readonly=True)
    try:
        repos = [public_repo(r) for r in c.execute("SELECT * FROM backup_repos ORDER BY name COLLATE NOCASE")]
        jobs = [public_job(r) for r in c.execute("SELECT * FROM backup_jobs ORDER BY name COLLATE NOCASE")]
        runs = [dict(r) for r in c.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 30")]
    finally:
        c.close()
    st_ = bk.stage
    stage = None
    if st_.get("src"):
        stage = {"origin": st_.get("origin"), "encrypted": st_.get("encrypted"), "meta": st_.get("meta"),
                 "size": os.path.getsize(st_["src"]) if os.path.exists(st_["src"]) else None}
    du = shutil.disk_usage(DATA_DIR)
    return {"now": int(time.time() * 1000), "host": host_name(), "repos": repos, "jobs": jobs, "runs": runs,
            "task": bk.task, "last": bk.last, "stage": stage, "pin": TLS_PIN, "disk_free": du.free,
            "reserve": _reserve(), "smbclient": bool(shutil.which("smbclient"))}


def backup_summary(c):
    rows = c.execute("SELECT name, enabled, last_status, last_run, contents FROM backup_jobs").fetchall()
    return {"jobs": len(rows), "enabled": sum(1 for r in rows if r["enabled"]),
            "admin_covered": any(r["enabled"] and "admin" in json.loads(r["contents"]) for r in rows),
            "failed": [r["name"] for r in rows if r["enabled"] and r["last_status"] == "error"],
            "last_ok": max((r["last_run"] for r in rows if r["last_status"] == "ok"), default=None),
            "running": bk.task["label"] if bk.task else None}


def _repo_row(c, rid):
    r = c.execute("SELECT * FROM backup_repos WHERE id=?", (rid,)).fetchone()
    if not r:
        raise HttpError(404, "destinazione non trovata")
    return r


def api_repo_save(rid, d):
    c = store.connect()
    try:
        old = _repo_row(c, rid) if rid else None
        old_cfg = json.loads(old["config"]) if old and old["type"] == d.get("type") else None
        name, rtype, cfg = clean_repo(d, old_cfg)
        try:
            if old:
                c.execute("UPDATE backup_repos SET name=?, type=?, config=? WHERE id=?",
                          (name, rtype, json.dumps(cfg), rid))
            else:
                rid = c.execute("INSERT INTO backup_repos(name, type, config, created) VALUES(?,?,?,?)",
                                (name, rtype, json.dumps(cfg), int(time.time() * 1000))).lastrowid
            c.commit()
        except sqlite3.IntegrityError:
            raise ValueError("esiste gia' una destinazione con questo nome")
    finally:
        c.close()
    return {"ok": True, "id": rid}


def api_repo_test(d):
    """Prova una destinazione (anche non ancora salvata: i segreti vuoti si prendono
    da quella salvata con lo stesso id)."""
    old_cfg = None
    if d.get("id"):
        c = store.connect(readonly=True)
        try:
            r = _repo_row(c, _int(d["id"], "id"))
        finally:
            c.close()
        if r["type"] == d.get("type"):
            old_cfg = json.loads(r["config"])
    _, rtype, cfg = clean_repo(dict(d, name=d.get("name") or "prova"), old_cfg)
    try:
        return {"ok": True, "msg": make_repo(rtype, cfg).test()}
    except BackupError as e:
        return {"ok": False, "msg": str(e)}


def api_repo_delete(rid):
    c = store.connect()
    try:
        _repo_row(c, rid)
        used = [r[0] for r in c.execute("SELECT name FROM backup_jobs WHERE repo_id=?", (rid,))]
        if used:
            raise ValueError("destinazione usata dai job: " + ", ".join(used))
        c.execute("DELETE FROM backup_repos WHERE id=?", (rid,))
        c.commit()
    finally:
        c.close()
    return {"ok": True}


def api_repo_files(rid):
    c = store.connect(readonly=True)
    try:
        r = _repo_row(c, rid)
    finally:
        c.close()
    repo = make_repo(r["type"], json.loads(r["config"]))
    try:
        files = repo.list()
    except BackupError as e:
        raise HttpError(502, str(e))
    names = {f["name"] for f in files}
    out = sorted((f for f in files if f["name"].endswith(BK_EXT)), key=lambda f: f["name"], reverse=True)[:200]
    # riepiloghi (manifest) dei 40 backup piu' recenti
    os.makedirs(BK_TMP, exist_ok=True)
    for f in out[:40]:
        mf = f["name"][:-len(BK_EXT)] + ".json"
        if mf not in names:
            continue
        tmp = os.path.join(BK_TMP, "manifest-" + secrets.token_hex(4))
        try:
            repo.get(mf, tmp)
            with open(tmp) as fh:
                m = json.load(fh)
            f["meta"] = {k: m.get(k) for k in ("created", "host", "job", "contents", "counts", "ranges",
                                               "encrypted", "sha256")}
        except Exception:
            pass
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    return {"files": out}


def api_job_save(jid, d):
    c = store.connect()
    try:
        old = c.execute("SELECT * FROM backup_jobs WHERE id=?", (jid,)).fetchone() if jid else None
        if jid and not old:
            raise HttpError(404, "job non trovato")
        v = clean_job(d, c, old)
        nxt = next_run(json.loads(v["schedule"]), int(time.time() * 1000)) if v["enabled"] else None
        try:
            if old:
                c.execute("UPDATE backup_jobs SET name=?, repo_id=?, contents=?, schedule=?, keep=?, password=?, "
                          "enabled=?, next_run=? WHERE id=?", (v["name"], v["repo_id"], v["contents"], v["schedule"],
                                                               v["keep"], v["password"], v["enabled"], nxt, jid))
            else:
                jid = c.execute("INSERT INTO backup_jobs(name, repo_id, contents, schedule, keep, password, enabled, "
                                "created, next_run) VALUES(?,?,?,?,?,?,?,?,?)",
                                (v["name"], v["repo_id"], v["contents"], v["schedule"], v["keep"], v["password"],
                                 v["enabled"], int(time.time() * 1000), nxt)).lastrowid
            c.commit()
        except sqlite3.IntegrityError:
            raise ValueError("esiste gia' un job con questo nome")
    finally:
        c.close()
    return {"ok": True, "id": jid}


def api_job_delete(jid):
    c = store.connect()
    try:
        n = c.execute("DELETE FROM backup_jobs WHERE id=?", (jid,)).rowcount
        c.commit()
    finally:
        c.close()
    if not n:
        raise HttpError(404, "job non trovato")
    return {"ok": True}


def api_job_run(jid):
    c = store.connect(readonly=True)
    try:
        j = c.execute("SELECT name FROM backup_jobs WHERE id=?", (jid,)).fetchone()
    finally:
        c.close()
    if not j:
        raise HttpError(404, "job non trovato")
    bk.start("backup", f"backup «{j['name']}»", bk.run_job, jid)
    return {"ok": True}


def api_config_import(d):
    if d.get("fwlog") != "backup-config":
        raise ValueError("il file non e' una configurazione dei backup di fwlog")
    repos, jobs = d.get("repos") or [], d.get("jobs") or []
    if not isinstance(repos, list) or not isinstance(jobs, list):
        raise ValueError("configurazione non valida")
    c = store.connect()
    try:
        out = import_config(c, repos, jobs)
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
    return dict(out, ok=True)


def api_restore_prepare(d):
    password = d.get("password") or None
    if password is not None and (not isinstance(password, str) or "\n" in password):
        raise ValueError("password non valida")
    if d.get("repo_id") is not None:
        rid = _int(d["repo_id"], "destinazione")
        name = str(d.get("name") or "")
        if not re.fullmatch(r"fwlog-[A-Za-z0-9.\-_]+" + re.escape(BK_EXT), name):
            raise ValueError("nome del backup non valido")
        bk.start("restore", "preparazione del ripristino", bk.prepare, rid, name, password)
    else:
        if not bk.stage.get("src"):
            raise ValueError("nessun file caricato")
        bk.start("restore", "preparazione del ripristino", bk.prepare, None, None, password)
    return {"ok": True}


def api_restore_run(d):
    sections = d.get("sections")
    meta = (bk.stage or {}).get("meta")
    if not meta:
        raise ValueError("prepara prima il backup da ripristinare")
    if not isinstance(sections, list) or not sections or any(s not in meta["contents"] for s in sections):
        raise ValueError("scegli cosa ripristinare tra i contenuti del backup")
    mode = d.get("admin_mode", "replace")
    if mode not in ("replace", "merge"):
        raise ValueError("modalita' non valida")
    bk.start("restore", "ripristino", bk.restore, sorted(set(sections)), mode)
    return {"ok": True}


def api_restore_cancel():
    if bk.busy():
        raise HttpError(409, "operazione in corso")
    bk.clear_stage()
    return {"ok": True}


def cleanup_backup_dirs():
    """All'avvio: file temporanei di backup e ripristini interrotti."""
    for d in (BK_TMP, RESTORE_DIR):
        if os.path.isdir(d):
            for e in os.scandir(d):
                if e.is_file():
                    os.remove(e.path)

# --------------------------------------------------------------------------
# Server web
# --------------------------------------------------------------------------

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
        except (ValueError, BackupError) as e:
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
        if urlparse(self.path).path == "/api/restore/upload":
            return self._handle(self._upload)
        self._handle(self._post)

    def _upload(self):
        """Backup da ripristinare caricato dal browser (corpo binario, scritto a blocchi)."""
        if self.headers.get("Content-Type") != "application/octet-stream":
            self.close_connection = True
            raise ValueError("Content-Type deve essere application/octet-stream")
        try:
            n = int(self.headers.get("Content-Length") or -1)
        except ValueError:
            n = -1
        if n <= 0:
            self.close_connection = True
            raise ValueError("file vuoto o dimensione mancante")
        try:
            if bk.busy():
                raise HttpError(409, f"operazione in corso: {bk.task['label']}")
            need_space(n * 6, "caricare e decomprimere il backup")
        except Exception:
            self.close_connection = True
            raise
        bk.clear_stage()
        os.makedirs(RESTORE_DIR, exist_ok=True)
        dst = os.path.join(RESTORE_DIR, "upload" + BK_EXT)
        left = n
        try:
            with open(dst, "wb") as f:
                while left > 0:
                    b = self.rfile.read(min(left, 1024 * 1024))
                    if not b:
                        raise ValueError("caricamento interrotto")
                    f.write(b)
                    left -= len(b)
            enc = is_encrypted(dst)
        except Exception:
            self.close_connection = True
            if os.path.exists(dst):
                os.remove(dst)
            raise
        name = os.path.basename(parse_qs(urlparse(self.path).query).get("name", ["file"])[-1])[:120]
        bk.stage = {"src": dst, "origin": f"{name} (caricato)", "encrypted": enc}
        self._send(200, {"ok": True, "encrypted": enc, "size": n})

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
        elif u.path == "/api/admin":
            self._send(200, api_admin(p))
        elif u.path == "/api/admin.csv":
            name = time.strftime("fwlog-registro-admin-%Y%m%d-%H%M%S.csv")
            self._send(200, api_admin_csv(p), "text/csv; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{name}"'})
        elif u.path == "/api/admin/facets":
            self._send(200, api_admin_facets())
        elif u.path == "/api/backup":
            self._send(200, api_backup())
        elif u.path == "/api/backup/config":
            c = store.connect(readonly=True)
            try:
                cfg = export_config(c, p.get("secrets") != "0")
            finally:
                c.close()
            name = time.strftime(f"fwlog-{host_name()}-config-backup-%Y%m%d.json")
            self._send(200, json.dumps(cfg, indent=1, ensure_ascii=False), "application/json; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{name}"'})
        elif re.fullmatch(r"/api/backup/repos/(\d+)/files", u.path):
            self._send(200, api_repo_files(int(u.path.split("/")[4])))
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
        if path.startswith("/api/backup") or path.startswith("/api/restore") or path.startswith("/api/admin"):
            return self._post_backup(path)
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

    def _post_backup(self, path):
        if path == "/api/backup/config":
            return self._send(200, api_config_import(self._body_json(1024 * 1024)))
        d = self._body_json()
        if path == "/api/admin/settings":
            return self._send(200, api_admin_settings(d))
        if path == "/api/backup/repos":
            return self._send(200, api_repo_save(None, d))
        if path == "/api/backup/repos/test":
            return self._send(200, api_repo_test(d))
        m = re.fullmatch(r"/api/backup/repos/(\d+)", path)
        if m:
            return self._send(200, api_repo_save(int(m.group(1)), d))
        if path == "/api/backup/jobs":
            return self._send(200, api_job_save(None, d))
        m = re.fullmatch(r"/api/backup/jobs/(\d+)(/run)?", path)
        if m:
            if m.group(2):
                return self._send(202, api_job_run(int(m.group(1))))
            return self._send(200, api_job_save(int(m.group(1)), d))
        if path == "/api/restore/prepare":
            return self._send(202, api_restore_prepare(d))
        if path == "/api/restore/run":
            return self._send(202, api_restore_run(d))
        self._send(404, {"error": "non trovato"})

    def _delete(self):
        u = urlparse(self.path)
        m = re.fullmatch(r"/api/backup/(repos|jobs)/(\d+)", u.path)
        if m:
            fn = api_repo_delete if m.group(1) == "repos" else api_job_delete
            return self._send(200, fn(int(m.group(2))))
        if u.path == "/api/restore":
            return self._send(200, api_restore_cancel())
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
    try:
        cleanup_backup_dirs()
    except OSError:
        log.warning("impossibile pulire i file temporanei di backup")
    threading.Thread(target=bk.scheduler, name="backup-sched", daemon=True).start()
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


# --------------------------------------------------------------------------
# Ripristino da riga di comando (macchina nuova, servizio fermo)
# --------------------------------------------------------------------------
def db_in_use():
    """True se un processo ha aperto il database (servizio ancora attivo)."""
    target = os.path.realpath(DB_PATH)
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                if os.readlink(f"/proc/{pid}/fd/{fd}") in (target, target + "-wal"):
                    return True
        except OSError:
            continue
    return False


def cli_restore(argv):
    import argparse
    import getpass
    ap = argparse.ArgumentParser(
        prog="fwlog.py restore",
        description="Ripristina un backup di fwlog (.fwbk) come database del servizio, con certificato TLS "
                    "e fwlog.env se non presenti. Da eseguire come root a servizio fermo.")
    ap.add_argument("file", help="file .fwbk")
    ap.add_argument("--info", action="store_true", help="mostra solo il contenuto del backup")
    ap.add_argument("--replace", action="store_true",
                    help="sostituisce un database esistente con dati (il vecchio viene rinominato)")
    ap.add_argument("--no-etc", action="store_true", help="non ripristina certificato TLS e fwlog.env")
    ap.add_argument("--yes", action="store_true", help="non chiede conferma")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    def fail(msg):
        print("ERRORE: " + msg, file=sys.stderr)
        return 1
    if not os.path.isfile(a.file):
        return fail(f"file non trovato: {a.file}")
    if not a.info:
        if os.geteuid() != 0:
            return fail("eseguire come root (sudo)")
        if db_in_use():
            return fail(f"{DB_PATH} e' in uso: fermare il servizio con  systemctl stop fwlog")
    if not os.path.isdir(DATA_DIR):
        return fail(f"{DATA_DIR} non esiste: montare il disco dati o eseguire install.sh")
    try:
        password = None
        if is_encrypted(a.file):
            password = os.environ.get("FWLOG_RESTORE_PASSWORD") or getpass.getpass("Password del backup: ")
        tmp = DB_PATH + ".restore"
        need_space(os.path.getsize(a.file) * 6, "decomprimere il backup")
        print("Decompressione...")
        meta = unpack(a.file, tmp, password, guard=False)
    except BackupError as e:
        return fail(str(e))
    labels = {"admin": "accessi amministratori", "firewall": "log dei firewall", "config": "configurazione backup"}
    counts = meta.get("counts", {})
    print(f"\nBackup del {_ms_iso(meta['created'])} da {meta.get('host')} (job: {meta.get('job')})")
    print("Contenuto: " + ", ".join(labels.get(x, x) for x in meta.get("contents", [])))
    for t, label in (("firewalls", "firewall"), ("logs", "log dei firewall"), ("servers", "server Windows"),
                     ("events", "eventi dei server"), ("fw_admin", "accessi admin ai firewall"),
                     ("backup_jobs", "job di backup"), ("backup_repos", "destinazioni di backup")):
        if t in counts:
            print(f"  {label}: {counts[t]}")
    print("File di configurazione: " + (", ".join(meta.get("files") or []) or "nessuno"))
    if a.info:
        os.remove(tmp)
        return 0

    def has_data(path):
        try:
            c = sqlite3.connect(path)
            try:
                for t in ("logs", "events", "servers", "firewalls", "fw_admin"):
                    try:
                        if c.execute(f"SELECT 1 FROM {t} LIMIT 1").fetchone():
                            return True
                    except sqlite3.OperationalError:
                        pass
            finally:
                c.close()
        except sqlite3.DatabaseError:
            return True
        return False
    exists = os.path.exists(DB_PATH)
    if exists and has_data(DB_PATH) and not a.replace:
        os.remove(tmp)
        return fail(f"{DB_PATH} contiene gia' dei dati: rieseguire con --replace (il database attuale "
                    "viene conservato con un altro nome)")
    if not a.yes:
        q = "\nIl database attuale verra' rinominato e sostituito. " if exists else "\n"
        if input(q + "Procedere con il ripristino? [s/N] ").strip().lower() not in ("s", "si", "y", "yes"):
            os.remove(tmp)
            print("Annullato.")
            return 1
    c = sqlite3.connect(tmp)
    try:
        files = dict(c.execute("SELECT name, data FROM _files").fetchall()) if "_files" in meta["tables"] else {}
        c.execute("DROP TABLE IF EXISTS _files")
        c.execute("DROP TABLE IF EXISTS _meta")
        c.commit()
        c.execute("PRAGMA journal_mode=WAL")
    finally:
        c.close()
    if exists:
        old = DB_PATH + time.strftime(".prima-del-ripristino-%Y%m%d-%H%M%S")
        for sfx in ("", "-wal", "-shm"):
            if os.path.exists(DB_PATH + sfx):
                os.replace(DB_PATH + sfx, old + sfx)
        print(f"Database precedente conservato in {old}")
    for sfx in ("-wal", "-shm"):
        if os.path.exists(tmp + sfx):
            os.replace(tmp + sfx, DB_PATH + sfx)
    os.replace(tmp, DB_PATH)
    try:
        import grp
        import pwd
        uid, gid = pwd.getpwnam("fwlog").pw_uid, grp.getgrnam("fwlog").gr_gid
        for sfx in ("", "-wal", "-shm"):
            if os.path.exists(DB_PATH + sfx):
                os.chown(DB_PATH + sfx, uid, gid)
                os.chmod(DB_PATH + sfx, 0o640)
    except KeyError:
        uid = gid = None
        print("ATTENZIONE: utente fwlog inesistente, sistemare i permessi del database")
    print(f"Database ripristinato in {DB_PATH}")
    if a.no_etc or not files:
        return 0
    os.makedirs(ETC_DIR, exist_ok=True)
    for name, data in sorted(files.items()):
        dst = os.path.join(ETC_DIR, name)
        if os.path.exists(dst):
            with open(dst, "rb") as f:
                same = f.read() == data
            if same:
                continue
            dst += ".dal-backup"
            print(f"{os.path.join(ETC_DIR, name)} esiste gia': la versione del backup e' in {dst}")
        else:
            print(f"Ripristinato {dst}")
        with open(dst, "wb") as f:
            f.write(data)
        os.chmod(dst, 0o644 if name.endswith(".crt") else 0o640)
        if gid is not None:
            os.chown(dst, 0, gid)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        sys.exit(cli_restore(sys.argv[2:]))
    main()
