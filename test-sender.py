#!/usr/bin/env python3
"""
Invia a fwlog alcune righe di log di esempio (formati di vari vendor) per
verificare che ricezione e parsing funzionino.

  python3 test-sender.py 192.168.1.50            # un esempio per formato, UDP
  python3 test-sender.py 192.168.1.50 --tcp
  python3 test-sender.py 192.168.1.50 -n 50000   # prova di carico
"""
import argparse
import random
import socket
import time

SAMPLES = [
    # pfSense (BSD syslog)
    "<134>Nov  6 10:15:01 pfsense filterlog[12345]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,"
    "12345,0,DF,6,tcp,60,203.0.113.5,192.168.1.10,51515,22,0,S,123456789,,64240,,mss",
    # pfSense IPv6
    "<134>Nov  6 10:15:02 pfsense filterlog[12345]: 7,,,1000000105,igb1,match,block,in,6,0x00,"
    "0x00000,255,ipv6-icmp,58,32,fe80::1,ff02::1,datalength=32",
    # OPNsense (RFC 5424)
    '<134>1 2026-11-06T10:15:03+01:00 opnsense.local filterlog 7012 - [meta sequenceId="1"] '
    "82,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,pass,out,4,0x0,,64,0,0,DF,17,udp,76,"
    "192.168.1.1,1.1.1.1,40000,53,56",
    # FortiGate
    '<189>date=2026-11-06 time=10:15:04 devname="FGT60F" devid="FGT60FTK0000000" logid="0000000013" '
    'type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.10.25 srcport=53412 '
    'srcintf="internal" srcintfrole="lan" dstip=142.250.180.14 dstport=443 dstintf="wan1" '
    'dstintfrole="wan" proto=6 action="accept" policyid=3 policyname="LAN-to-WAN" service="HTTPS"',
    '<189>date=2026-11-06 time=10:15:05 devname="FGT60F" type="traffic" subtype="local" '
    'srcip=45.33.32.156 srcport=61000 srcintf="wan1" srcintfrole="wan" dstip=203.0.113.2 '
    'dstport=3389 dstintf="root" proto=6 action="deny" policyid=0',
    # Sophos Firewall
    '<30>device="SFW" date=2026-11-06 time=10:15:06 device_name="XG135" log_type="Firewall" '
    'log_component="Firewall Rule" log_subtype="Allowed" status="Allow" fw_rule_id=5 '
    'in_interface="Port1" out_interface="Port2" src_ip=10.10.10.5 dst_ip=8.8.8.8 protocol="UDP" '
    'src_port=51000 dst_port=53 src_zone="LAN" dst_zone="WAN"',
    # Palo Alto
    "<14>Nov  6 10:15:07 PA-440 1,2026/11/06 10:15:07,012801000001,TRAFFIC,end,2562,"
    "2026/11/06 10:15:07,10.0.0.5,172.217.16.142,203.0.113.10,172.217.16.142,Allow-Web,,,ssl,"
    "vsys1,trust,untrust,ethernet1/2,ethernet1/1,Forward-All,2026/11/06 10:15:07,12345,1,50123,"
    "443,40123,443,0x400019,tcp,allow,5000,1200,3800,20",
    # Cisco ASA
    '<164>Nov 06 2026 10:15:08: %ASA-4-106023: Deny tcp src outside:185.220.101.4/40000 '
    'dst inside:192.168.1.20/3389 by access-group "outside_access_in" [0x0, 0x0]',
    "<166>Nov 06 2026 10:15:09: %ASA-6-302013: Built inbound TCP connection 4567 for "
    "outside:198.51.100.20/51000 (198.51.100.20/51000) to dmz:172.16.0.10/443 (203.0.113.10/443)",
    # MikroTik
    "<134>Nov  6 10:15:10 mikrotik firewall,info forward: in:ether1 out:bridge, connection-state:new "
    "src-mac 00:11:22:33:44:55, proto TCP (SYN), 198.51.100.7:44321->192.168.88.10:443, len 60",
    # SonicWall
    '<134>id=firewall sn=0017C5000000 time="2026-11-06 10:15:11 UTC" fw=203.0.113.1 pri=6 '
    'm=537 msg="Connection Closed" src=192.168.168.20:52000:X0 dst=104.16.0.1:443:X1 '
    'proto=tcp/https fw_action="NA"',
    # Linux UFW
    "<4>Nov  6 10:15:12 gateway kernel: [12345.678] [UFW BLOCK] IN=ens18 OUT= MAC=00:00 "
    "SRC=94.102.61.7 DST=10.0.0.5 LEN=44 TOS=0x00 TTL=242 ID=54321 PROTO=TCP SPT=48000 DPT=8080 SYN",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("-p", "--port", type=int, default=514)
    ap.add_argument("--tcp", action="store_true")
    ap.add_argument("-n", "--count", type=int, default=0,
                    help="numero di messaggi casuali per una prova di carico")
    a = ap.parse_args()

    msgs = SAMPLES if not a.count else [random.choice(SAMPLES) for _ in range(a.count)]
    t0 = time.time()
    if a.tcp:
        s = socket.create_connection((a.host, a.port))
        for m in msgs:
            b = m.encode()
            s.sendall(str(len(b)).encode() + b" " + b)
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i, m in enumerate(msgs):
            s.sendto(m.encode(), (a.host, a.port))
            if a.count and i % 2000 == 0:
                time.sleep(0.01)   # evita di saturare il buffer UDP in locale
    print(f"inviati {len(msgs)} messaggi in {time.time() - t0:.2f}s")


if __name__ == "__main__":
    main()
