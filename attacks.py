"""
קובץ זה אחראי על זיהוי מתקפות רשת בסיסיות מתוך חבילות שעברו נרמול.
כל פונקציה בקובץ מקבלת אובייקט Packet אחד, מעדכנת מצב פנימי זמני,
ובודקת האם הצטברו מספיק סימנים כדי להחזיר התראה.

הקובץ מזהה:
- Port Scan
- ARP Spoofing
- SYN Flood
- Evil Twin Wi-Fi
- UDP/ICMP Flood
- DNS Poisoning חשוד
- DHCP Spoofing

הזיהוי מבוסס על חלונות זמן וספים, ולא על חסימה אמיתית של תעבורה.
המטרה היא להתריע על התנהגות חשודה תוך צמצום False Positives.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Deque, Dict, Optional

from packet import Packet


"""
Port Scan
"""

_portscan_state: Dict[str, dict] = {}
# Example: {"192.168.1.50": {"first_ts": 12:00:00, "last_ts": 12:00:00, "ports": {80, 443}}}
PORTSCAN_PORT_THRESHOLD = 50
PORTSCAN_WINDOW_SECONDS = 30

_last_portscan_alert: Dict[str, datetime] = {}
PORTSCAN_SUPPRESS_SECONDS = 20


def update_and_check_portscan(p: Packet) -> Optional[dict]:
    """
    The detector counts how many unique destination ports
    a single source IP contacts within a short time window.
    """
    # Port scanning requires source IP, destination IP and destination port.
    if not p.src_ip or not p.dst_ip or p.dst_port is None:
        return None

    # Port scans are relevant only for transport protocols with ports.
    if p.proto_name not in ("tcp", "udp"):
        return None

    now: datetime = p.ts

    # Retrieve existing state for this source IP.
    state = _portscan_state.get(p.src_ip)

    # First packet seen from this source: create tracking state.
    if state is None:
        state = {"first_ts": now, "last_ts": now, "ports": set()}
        _portscan_state[p.src_ip] = state

    # Reset the detection window if it became too old.
    if (now - state["first_ts"]).total_seconds() > PORTSCAN_WINDOW_SECONDS:
        state["first_ts"] = now
        state["ports"].clear()

    state["last_ts"] = now

    # Add the destination port to the set.
    # Using a set guarantees uniqueness.
    state["ports"].add(int(p.dst_port))

    unique_ports = len(state["ports"])

    # If enough different ports were contacted within the window,
    # raise a PORT_SCAN alert.
    if unique_ports >= PORTSCAN_PORT_THRESHOLD:
        last = _last_portscan_alert.get(p.src_ip)

        # Avoid repeated PORT_SCAN alerts from the same source.
        if last and (now - last).total_seconds() < PORTSCAN_SUPPRESS_SECONDS:
            state["first_ts"] = now
            state["ports"].clear()
            return None

        # Remember when the last alert was raised for this source.
        _last_portscan_alert[p.src_ip] = now

        state["first_ts"] = now
        state["ports"].clear()

        return {
            "type": "PORT_SCAN",
            "severity": 7,
            "description": f"Port scan suspected from {p.src_ip}: {unique_ports} unique dst ports in {PORTSCAN_WINDOW_SECONDS}s",
            "evidence_key": p.src_ip,
        }

    return None


"""
ARP Spoofing
"""

_arp_state: Dict[str, dict] = {}
""" Example:
{
    "192.168.1.1": {
        "last_mac": "CC:DD:EE:FF:11:22",
        "changes": deque([ datetime(2026, 6, 22, 10, 0, 5), datetime(2026, 6, 22, 10, 0, 18)])
    }
}"""
ARP_WINDOW_SECONDS = 60
ARP_CHANGES_THRESHOLD = 3  # Num of times an IP changes MAC address.


def update_and_check_arpspoof(p: Packet) -> Optional[dict]:
    """
    The detector watches whether the same IP address is
    repeatedly associated with different MAC addresses.
    """
    # ARP information is stored inside the packet metadata.
    meta = p.meta or {}
    # Extract the IP and MAC advertised by the ARP packet.
    arp_ip = meta.get("arp_ip")
    arp_mac = meta.get("arp_mac")
    # Non-ARP packets are ignored.
    if not arp_ip or not arp_mac:
        return None

    now = p.ts
    # Retrieve tracking state for this IP address.
    state = _arp_state.get(arp_ip)
    # First time this IP is observed.
    # Store its MAC address and start tracking changes.
    if state is None:
        _arp_state[arp_ip] = {"last_mac": arp_mac, "changes": deque()}
        return None

    changes: Deque[datetime] = state["changes"]
    # Remove MAC-change events that are outside the detection window.
    while changes and (now - changes[0]).total_seconds() > ARP_WINDOW_SECONDS:
        changes.popleft()
    # The IP is now associated with a different MAC address.
    if arp_mac != state["last_mac"]:
        prev = state["last_mac"]
        # Record the time of the MAC change.
        state["last_mac"] = arp_mac
        changes.append(now)
        # Too many MAC changes for the same IP in a short time.
        # This may indicate ARP spoofing.
        if len(changes) >= ARP_CHANGES_THRESHOLD:
            changes.clear()
            return {
                "type": "ARP_SPOOF",
                "severity": 8,
                "description": f"ARP spoof suspected: IP {arp_ip} changed MAC multiple times (e.g., {prev} -> {arp_mac}) within {ARP_WINDOW_SECONDS}s",
                "evidence_key": arp_ip,
            }
    return None


"""
SYN Flood
"""

_syn_state: Dict[str, dict] = {}
""" Example:
{
    "192.168.1.10": {
        "events": deque([
            (datetime(2026, 6, 22, 10, 0, 1), True, False),
            (datetime(2026, 6, 22, 10, 0, 1), True, False),
            (datetime(2026, 6, 22, 10, 0, 2), False, True),
        ])
    }
}
"""
SYN_WINDOW_SECONDS = 10
SYN_THRESHOLD = 200
SYN_ACK_RATIO = 5.0


def update_and_check_synflood(p: Packet) -> Optional[dict]:
    """
    The detector tracks TCP packets sent toward each destination IP.
    A SYN flood is suspected when many SYN-only packets are observed
    while relatively few ACK packets are seen in the same time window.
    """
    # SYN flood detection is relevant only for TCP packets with flags.
    if p.proto_name != "tcp" or not p.dst_ip or not isinstance(p.flags, str):
        return None

    now = p.ts
    dst = p.dst_ip
    # Keep separate SYN/ACK statistics for each destination IP.
    state = _syn_state.get(dst)
    if state is None:
        state = {"events": deque()}
        _syn_state[dst] = state

    flags = p.flags or ""
    # SYN-only means a connection attempt that was not yet acknowledged.
    # In Scapy-style TCP flags, "S" means SYN and "A" means ACK.
    is_syn_only = ("S" in flags) and ("A" not in flags)
    # Any packet containing ACK contributes to the normal-traffic side.
    is_ackish = ("A" in flags)

    events: Deque = state["events"]
    # Store a compact event instead of the full packet to save memory.
    events.append((now, is_syn_only, is_ackish))
    # Remove events that are older than the current detection window.
    while events and (now - events[0][0]).total_seconds() > SYN_WINDOW_SECONDS:
        events.popleft()
    # Count SYN-only packets and ACK packets inside the time window.
    syn = sum(1 for _, is_syn, _ in events if is_syn)
    ack = sum(1 for _, _, is_ack in events if is_ack)
    # Alert only when both conditions hold:
    # 1. The absolute SYN count is high.
    # 2. The SYN/ACK ratio is abnormal.
    # max(ack, 1) prevents division by zero when there are no ACK packets.
    if syn >= SYN_THRESHOLD and (syn / max(ack, 1)) >= SYN_ACK_RATIO:
        events.clear()
        return {
            "type": "SYN_FLOOD",
            "severity": 9,
            "description": f"SYN flood suspected against {dst}: {syn} SYNs vs {ack} ACKs in {SYN_WINDOW_SECONDS}s",
            "evidence_key": dst,
        }
    return None


"""
EVIL TWIN
"""

_eviltwin_state: Dict[str, dict] = {}
""" Example:
{
    "HomeWifi": {
        "first_ts": datetime(2026, 6, 22, 10, 0, 0),
        "aps": {
            "AA:AA:AA:AA:AA:AA": {
                "channel": 6,
                "rssi": -55
            },
            "99:99:99:99:99:99": {
                "channel": 11,
                "rssi": -35
            } } } }
"""
EVILTWIN_WINDOW_SECONDS = 60
EVILTWIN_RSSI_JUMP_DB = 12
EVILTWIN_MIN_APS = 2


def update_and_check_eviltwin(p: Packet) -> Optional[dict]:
    """
    The detector tracks Wi-Fi beacon frames by SSID.
    If the same SSID appears from a new BSSID with suspicious
    channel or signal-strength differences, an Evil Twin alert
    may be generated.
    """
    # Wi-Fi details are extracted by the packet normalizer into metadata.
    meta = p.meta or {}
    ssid = meta.get("wifi_ssid")
    bssid = meta.get("wifi_bssid")
    # Evil Twin detection requires Wi-Fi beacon frames.
    # Without SSID, BSSID and beacon indication, this packet is irrelevant.
    if not ssid or not bssid or not meta.get("wifi_is_beacon", False):
        return None

    now = p.ts
    # Channel and RSSI help compare access points using the same SSID.
    channel = meta.get("wifi_channel")
    rssi = meta.get("wifi_rssi_dbm")
    # Keep separate tracking state for each Wi-Fi network name.
    state = _eviltwin_state.get(ssid)
    if state is None:
        state = {"first_ts": now, "aps": {}}  # Maps BSSID to channel/RSSI information.
        _eviltwin_state[ssid] = state
    # Reset old observations after the detection window expires.
    if (now - state["first_ts"]).total_seconds() > EVILTWIN_WINDOW_SECONDS:
        state["first_ts"] = now
        state["aps"].clear()

    aps = state["aps"]
    # If this BSSID is already known, just update its latest radio details.
    if bssid in aps:
        aps[bssid]["channel"] = channel
        aps[bssid]["rssi"] = rssi
        return None

    suspicious = False
    reasons = []
    # Compare the new BSSID against previously observed APs with the same SSID.
    for _, info in aps.items():
        other_ch = info.get("channel")
        other_rssi = info.get("rssi")
        # Same SSID on a different channel may be suspicious in this simplified model.
        if channel is not None and other_ch is not None and channel != other_ch:
            suspicious = True
            reasons.append(f"channel {channel} vs {other_ch}")
        # A sudden stronger signal from a new BSSID may indicate a nearby fake AP.
        # rssi - Received Signal Strength Indicator
        if rssi is not None and other_rssi is not None and (rssi - other_rssi) >= EVILTWIN_RSSI_JUMP_DB:
            suspicious = True
            reasons.append(f"RSSI jump {rssi} dBm vs {other_rssi} dBm")
    # Store the newly discovered BSSID after comparing it to the old ones.
    aps[bssid] = {"channel": channel, "rssi": rssi}
    # Generate an alert only if at least two APs were seen for the same SSID
    # and the new AP differs in a suspicious way.
    if suspicious and len(aps) >= EVILTWIN_MIN_APS:
        state["first_ts"] = now
        state["aps"].clear()
        return {
            "type": "EVIL_TWIN",
            "severity": 8,
            "description": f"Evil Twin suspected for SSID '{ssid}': new AP {bssid} does not match existing APs. Reasons: {', '.join(reasons)}",
            "evidence_key": ssid,
        }
    return None


"""
UDP & ICMP Flood
"""

_flood_state: dict[str, dict] = {}
""" Example:
{
    ("192.168.1.20", "udp"): {
        "events": deque([
            datetime(2026, 6, 22, 10, 0, 1),
            datetime(2026, 6, 22, 10, 0, 1),
            datetime(2026, 6, 22, 10, 0, 2),
        ]) } }
"""
FLOOD_WINDOW_SECONDS = 5
# High threshold reduces false positives from legitimate UDP traffic such as QUIC/YouTube.
FLOOD_PACKET_THRESHOLD = 600
_last_flood_alert: dict[tuple[str, str], datetime] = {}
""" Example:
{ ("192.168.1.20", "udp"): datetime(2026, 6, 22, 10, 0, 10) }
"""
FLOOD_SUPPRESS_SECONDS = 20


def update_and_check_flood(p: Packet):
    """
    The detector counts how many UDP/ICMP packets are sent
    to the same destination IP within a short time window.
    If the packet count is unusually high, a flood alert is raised.
    """
    # Flood detection here is relevant only for UDP and ICMP traffic.
    # TCP SYN floods are handled separately by update_and_check_synflood().
    if not p.dst_ip or p.proto_name not in ("udp", "icmp"):
        return None

    now = p.ts
    dst = p.dst_ip
    proto = p.proto_name
    # Track each destination/protocol pair separately.
    # Example key: ("192.168.1.20", "udp")
    state_key = (dst, proto)
    state = _flood_state.get(state_key)
    if state is None:
        state = {"events": deque()}  # Stores timestamps of recent packets.
        _flood_state[state_key] = state

    events = state["events"]
    # Add current packet timestamp to the sliding window.
    events.append(now)
    # Remove packet timestamps that are older than the flood window.
    while events and (now - events[0]).total_seconds() > FLOOD_WINDOW_SECONDS:
        events.popleft()

    count = len(events)
    # If too many packets reached the same destination/protocol pair,
    # this may indicate a UDP/ICMP flood.
    if count >= FLOOD_PACKET_THRESHOLD:
        # Suppress repeated alerts for the same destination/protocol pair.
        # This prevents the dashboard from being flooded with duplicate alerts.
        last = _last_flood_alert.get(state_key)
        if last and (now - last).total_seconds() < FLOOD_SUPPRESS_SECONDS:
            return None
        _last_flood_alert[state_key] = now
        # Clear the current window after alerting, so the same burst
        # does not immediately trigger another alert.
        events.clear()
        return {
            "type": f"{proto.upper()}_FLOOD",
            "severity": 8,
            "description": f"{proto.upper()} flood suspected against {dst}: {count} packets in {FLOOD_WINDOW_SECONDS}s",
            "evidence_key": dst,
        }
    return None


"""
DNS Poison
"""

_dns_state: Dict[str, dict] = {}
""" Example:
{
    "example.com": {
        "first_ts": datetime(2026, 6, 22, 10, 0, 0),
        "answers": {
            "93.184.216.34",
            "10.0.0.99",
            "203.0.113.10",
            "198.51.100.7"
        } } }
"""
DNS_WINDOW_SECONDS = 60
# CDNs may return several legitimate IPs, so the threshold is intentionally high.
DNS_DISTINCT_ANSWERS_THRESHOLD = 8


def update_and_check_dns_poison(p: Packet) -> Optional[dict]:
    """
    The detector tracks DNS answers for each queried domain.
    If many distinct answers are observed for the same domain
    within a short time window, the domain is treated as suspicious.
    """
    # DNS fields are extracted by the packet normalizer into metadata.
    meta = p.meta or {}
    qname = meta.get("dns_qname")
    answers = meta.get("dns_answers")
    # Non-DNS packets, or DNS packets without answers, are ignored.
    if not qname or not answers:
        return None
    qname_lower = qname.lower()
    # Ignore known Microsoft telemetry domains that commonly return
    # changing CDN/load-balancing answers and caused false positives.
    if "watson.events.data.microsoft.com" in qname_lower:
        return None
    if any(x in qname_lower for x in [
        "vortex.data.microsoft.com",
        "vortex-win.data.microsoft.com",
        "self.events.data.microsoft.com",
        "v10.events.data.microsoft.com",
        "settingsfd-prod",
        "blobcollector.events.data.trafficmanager.net",
    ]):
        return None
    if qname.endswith(".local") or ".local." in qname:
        return None

    now = p.ts
    # Keep separate DNS answer history for each queried domain.
    st = _dns_state.get(qname)
    if st is None:
        st = {"first_ts": now,
              "answers": set()}  # Unique DNS answers seen in the current window.
        _dns_state[qname] = st
    # Reset observations when the DNS detection window expires.
    if (now - st["first_ts"]).total_seconds() > DNS_WINDOW_SECONDS:
        st["first_ts"] = now
        st["answers"].clear()
    # Add all returned answers to a set so duplicates are counted only once.
    for a in answers:
        if a:
            st["answers"].add(str(a))

    distinct = len(st["answers"])
    # Too many different answers for one domain may indicate DNS poisoning,
    # but can also happen with CDNs, so the threshold is intentionally high.
    if distinct >= DNS_DISTINCT_ANSWERS_THRESHOLD:
        ans_sample = ", ".join(list(sorted(st["answers"]))[:5])
        st["first_ts"] = now
        st["answers"].clear()
        return {
            "type": "DNS_POISON",
            "severity": 8,
            "description": f"DNS poisoning suspected for {qname}: {distinct} distinct answers seen within {DNS_WINDOW_SECONDS}s (sample: {ans_sample})",
            "evidence_key": p.src_ip or p.dst_ip or qname,
        }
    return None


"""
DHCP Spoof
"""

_dhcp_state: Dict[str, dict] = {}
""" Example:
{
    "global": {
        "first_ts": datetime(2026, 6, 22, 10, 0, 0),
        "servers": {
            "192.168.1.1",
            "192.168.1.99"
        } } }
"""
DHCP_WINDOW_SECONDS = 60
DHCP_SERVER_THRESHOLD = 2


def update_and_check_dhcp_spoof(p: Packet) -> Optional[dict]:
    """
    The detector tracks DHCP Offer/Ack messages and counts how many
    different DHCP server identifiers appear on the network. In a simple
    network, seeing more than one DHCP server is suspicious.
    """
    # DHCP details are extracted by the packet normalizer into metadata.
    meta = p.meta or {}
    # DHCP type may be offer/ack/discover/request, but only server responses
    # prove that a DHCP server exists.
    dhcp_type = str(meta.get("dhcp_type") or "").lower()
    # DHCP server identifier is the IP/address of the server that sent the offer/ack.
    server_id = meta.get("dhcp_server_id")
    # Ignore non-DHCP packets and DHCP packets that are not server responses.
    if dhcp_type not in ("offer", "ack") or not server_id:
        return None

    now = p.ts
    # DHCP is evaluated globally because it affects the whole local network.
    # In this simplified project, we do not split state by subnet/VLAN.
    key = "global"
    st = _dhcp_state.get(key)
    if st is None:
        st = {"first_ts": now,
              "servers": set()}  # Unique DHCP servers seen in the current window.
        _dhcp_state[key] = st
    # Reset observations when the DHCP detection window expires.
    if (now - st["first_ts"]).total_seconds() > DHCP_WINDOW_SECONDS:
        st["first_ts"] = now
        st["servers"].clear()
    # Add this DHCP server to the set of observed servers.
    st["servers"].add(str(server_id))
    distinct = len(st["servers"])
    # More than one DHCP server in a small network is suspicious and may
    # indicate a rogue DHCP server.
    if distinct >= DHCP_SERVER_THRESHOLD:
        sample = ", ".join(list(sorted(st["servers"]))[:5])
        # Reset after alerting to avoid repeated alerts from the same condition.
        st["first_ts"] = now
        st["servers"].clear()
        return {
            "type": "DHCP_SPOOF",
            "severity": 8,
            "description": f"DHCP spoof suspected: {distinct} DHCP servers observed within {DHCP_WINDOW_SECONDS}s (servers: {sample})",
            "evidence_key": p.src_ip or p.dst_ip or "dhcp",
        }
    return None
