#!/usr/bin/env python3
"""
fwlog - collettore syslog minimale per firewall, con dashboard web.

Riceve syslog su UDP e TCP, estrae i campi principali (sorgente, destinazione,
porte, protocollo, azione, interfacce, zone, regola) dai formati piu' comuni
(pfSense/OPNsense, FortiGate, Sophos, Palo Alto, Cisco ASA/FTD, MikroTik,
SonicWall, iptables/UFW/UniFi e in generale qualsiasi log chiave=valore) e li
salva in SQLite sul disco dati. Serve una dashboard web con filtri.

Usa solo la libreria standard di Python 3: nessuna dipendenza da installare.
Configurazione tramite variabili d'ambiente (vedi /etc/fwlog/fwlog.env).
"""

import base64
import csv
import hmac
import io
import ipaddress
import json
import logging
import os
import queue
import re
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
WEB_PORT = int(E("FWLOG_WEB_PORT", "8443"))
WEB_USER = E("FWLOG_WEB_USER", "admin")
WEB_PASS = E("FWLOG_WEB_PASS", "")
TLS_CERT = E("FWLOG_TLS_CERT", "")
TLS_KEY = E("FWLOG_TLS_KEY", "")
RETENTION_DAYS = int(E("FWLOG_RETENTION_DAYS", "90"))   # 0 = nessun limite di giorni
MIN_FREE_GB = float(E("FWLOG_MIN_FREE_GB", "2"))        # spazio minimo da lasciare libero
ALLOWED_SOURCES = [ipaddress.ip_network(s.strip(), strict=False)
                   for s in E("FWLOG_ALLOWED_SOURCES", "").split(",") if s.strip()]
STATIC_DIR = E("FWLOG_STATIC_DIR",
               os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))
QUEUE_MAX = int(E("FWLOG_QUEUE_MAX", "200000"))
MAX_RAW = 8192
BATCH = 5000

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
# Archivio (SQLite)
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS firewalls(
    id INTEGER PRIMARY KEY, ip TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
    first_seen INTEGER, last_seen INTEGER, total INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, fw_id INTEGER NOT NULL,
    sev INTEGER, host TEXT, prog TEXT, action TEXT, proto TEXT,
    src TEXT, src_n TEXT, sport INTEGER, dst TEXT, dst_n TEXT, dport INTEGER,
    in_if TEXT, out_if TEXT, src_zone TEXT, dst_zone TEXT, rule TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS ix_logs_fw ON logs(fw_id);
CREATE INDEX IF NOT EXISTS ix_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS ix_logs_src ON logs(src_n);
CREATE INDEX IF NOT EXISTS ix_logs_dst ON logs(dst_n);
"""
INSERT = ("INSERT INTO logs(ts,fw_id,sev,host,prog,action,proto,src,src_n,sport,"
          "dst,dst_n,dport,in_if,out_if,src_zone,dst_zone,rule,raw) "
          "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")


class Store:
    def __init__(self):
        self.q = queue.Queue(QUEUE_MAX)
        self.received = 0
        self.dropped = 0
        self.rejected = 0
        self._rates = deque()
        self._lock = threading.Lock()
        self.fw_cache = {}
        new = not os.path.exists(DB_PATH)
        c = self.connect()
        if new:
            c.execute("PRAGMA auto_vacuum=INCREMENTAL")
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
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

    def submit(self, ip, data):
        ip = norm_ip(ip) or ip
        if not self.allowed(ip):
            self.rejected += 1
            return
        self.received += 1
        try:
            self.q.put_nowait((int(time.time() * 1000), ip, data))
        except queue.Full:
            self.dropped += 1

    def command(self, name, arg):
        self.q.put(("cmd", name, arg))

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

    def _command(self, conn, name, arg):
        try:
            if name == "delete_fw":
                while conn.execute("DELETE FROM logs WHERE id IN "
                                   "(SELECT id FROM logs WHERE fw_id=? LIMIT 50000)", (arg,)).rowcount:
                    conn.commit()
                conn.execute("DELETE FROM firewalls WHERE id=?", (arg,))
                conn.commit()
                self.fw_cache = {k: v for k, v in self.fw_cache.items() if v != arg}
                conn.execute("PRAGMA incremental_vacuum").fetchall()
                log.info("firewall %s eliminato con i suoi log", arg)
        except Exception:
            log.exception("comando %s fallito", name)
            conn.rollback()

    def _maintenance(self, conn):
        deleted = 0
        if RETENTION_DAYS > 0:
            cutoff = int((time.time() - RETENTION_DAYS * 86400) * 1000)
            for _ in range(10):
                n = conn.execute("DELETE FROM logs WHERE id IN (SELECT id FROM logs "
                                 "WHERE ts < ? ORDER BY id LIMIT 20000)", (cutoff,)).rowcount
                conn.commit()
                deleted += n
                if n < 20000:
                    break
        # Protezione disco pieno: elimina i log piu' vecchi finche' non c'e' spazio
        for _ in range(20):
            if shutil.disk_usage(DATA_DIR).free >= MIN_FREE_GB * 1024 ** 3:
                break
            n = conn.execute("DELETE FROM logs WHERE id IN "
                             "(SELECT id FROM logs ORDER BY id LIMIT 50000)").rowcount
            conn.commit()
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
        rows = c.execute("SELECT id, ip, name, first_seen, last_seen, total FROM firewalls "
                         "ORDER BY name COLLATE NOCASE").fetchall()
    finally:
        c.close()
    rates = store.rates()
    du = shutil.disk_usage(DATA_DIR)
    db_size = sum(os.path.getsize(DB_PATH + s) for s in ("", "-wal") if os.path.exists(DB_PATH + s))
    return {
        "now": int(time.time() * 1000),
        "firewalls": [dict(r, rate=rates.get(r["id"], 0)) for r in rows],
        "stats": {"received": store.received, "dropped": store.dropped,
                  "rejected": store.rejected, "queue": store.q.qsize(),
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


def api_logs_csv(p):
    where, args = build_where(p)
    c = store.connect(readonly=True)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = [x.strip() for x in LOG_COLS.split(",")]
    w.writerow(cols)
    try:
        for r in c.execute(f"SELECT {LOG_COLS} FROM logs WHERE {where} ORDER BY id DESC LIMIT 100000", args):
            r = list(r)
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

# --------------------------------------------------------------------------
# Server web
# --------------------------------------------------------------------------
class Web(BaseHTTPRequestHandler):
    server_version = "fwlog"
    protocol_version = "HTTP/1.1"

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

    def _handle(self, fn):
        if not self._auth():
            return
        try:
            fn()
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
        elif u.path == "/api/facets":
            self._send(200, api_facets(p))
        else:
            self._send(404, {"error": "non trovato"})

    def _body_json(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ValueError("Content-Type deve essere application/json")
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(min(n, 65536)) or b"{}")

    def _post(self):
        m = re.fullmatch(r"/api/firewalls/(\d+)", urlparse(self.path).path)
        if not m:
            return self._send(404, {"error": "non trovato"})
        name = str(self._body_json().get("name", "")).strip()[:80]
        if not name:
            raise ValueError("il nome non puo' essere vuoto")
        c = store.connect()
        try:
            c.execute("UPDATE firewalls SET name=? WHERE id=?", (name, int(m.group(1))))
            c.commit()
        finally:
            c.close()
        self._send(200, {"ok": True})

    def _delete(self):
        m = re.fullmatch(r"/api/firewalls/(\d+)", urlparse(self.path).path)
        if not m:
            return self._send(404, {"error": "non trovato"})
        store.command("delete_fw", int(m.group(1)))
        self._send(202, {"ok": True})


# --------------------------------------------------------------------------
# Ricezione syslog
# --------------------------------------------------------------------------
def _family(bind):
    return socket.AF_INET6 if ":" in bind else socket.AF_INET


def udp_loop():
    s = socket.socket(_family(SYSLOG_BIND), socket.SOCK_DGRAM)
    if _family(SYSLOG_BIND) == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    s.bind((SYSLOG_BIND, SYSLOG_UDP))
    log.info("syslog UDP in ascolto su %s:%d", SYSLOG_BIND, SYSLOG_UDP)
    while True:
        try:
            data, addr = s.recvfrom(65535)
            store.submit(addr[0], data)
        except Exception:
            log.exception("errore ricezione UDP")


class SyslogTCP(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        if not store.allowed(norm_ip(ip) or ip):
            store.rejected += 1
            return
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
                if sp > 0 and buf[:sp].isdigit():
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
                if len(buf) > 65536:
                    store.submit(ip, buf)
                    return b""
                return buf
            store.submit(ip, buf[:nl])
            buf = buf[nl + 1:]


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = _family(SYSLOG_BIND)


class WebServer(ThreadingHTTPServer):
    daemon_threads = True
    address_family = _family(WEB_BIND)


# --------------------------------------------------------------------------
def main():
    global store
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    os.makedirs(DATA_DIR, exist_ok=True)
    store = Store()
    store.start()
    if SYSLOG_UDP:
        threading.Thread(target=udp_loop, name="udp", daemon=True).start()
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
    if not WEB_PASS:
        log.warning("FWLOG_WEB_PASS non impostata: la dashboard e' accessibile senza password")
    if ALLOWED_SOURCES:
        log.info("sorgenti syslog ammesse: %s", ", ".join(map(str, ALLOWED_SOURCES)))
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
