from globals import *
from scapy.all import *


def get_sniffable_interfaces():
    scapy_ifaces = get_if_list()
    windows_ifaces = get_windows_if_list()
    display_map = {}
    for iface in windows_ifaces:
        name = iface.get("name", "")
        desc = iface.get("description", "")
        guid = iface.get("guid", "")
        display_name = f"{name} - {desc}"
        for scapy_iface in scapy_ifaces:
            if name.lower() in scapy_iface.lower() or guid.lower() in scapy_iface.lower():
                display_map[display_name] = scapy_iface
                break
    return display_map
# ... [all your code above is unchanged up to packet_callback()] ...

def parse_http_host_useragent(payload_bytes):
    """Try to extract Host and User-Agent from HTTP request payload."""
    try:
        data = payload_bytes.decode(errors='ignore')
        host, user_agent = None, None
        if data.startswith("GET") or data.startswith("POST"):
            lines = data.split("\r\n")
            for line in lines:
                if line.lower().startswith("host:"):
                    host = line[5:].strip()
                elif line.lower().startswith("user-agent:"):
                    user_agent = line[11:].strip()
        return host, user_agent
    except Exception:
        return None, None

def parse_tls_sni(payload_bytes):
    """Try to extract SNI (Server Name Indication) from TLS Client Hello."""
    try:
        # TLS handshake starts with 0x16, version 0x0301 or 0x0303 (TLS 1.0/1.2)
        if len(payload_bytes) > 43 and payload_bytes[0] == 0x16:
            # Look for SNI extension in Client Hello
            data = payload_bytes
            # SNI is in the extensions part; minimal scan
            sni_marker = b'\x00\x00'  # Extension type for SNI
            idx = data.find(sni_marker)
            if idx > 0:
                sni_len = data[idx+2]
                sni_start = idx+5
                sni = data[sni_start:sni_start+sni_len].decode(errors='ignore')
                return sni
    except Exception:
        pass
    return None

def packet_callback(packet):
    if Ether in packet:
        eth = packet[Ether]
        src_mac = eth.src
        dst_mac = eth.dst
    else:
        src_mac = dst_mac = ""
    try:
        proto = packet.lastlayer().name
    except Exception:
        proto = ""
    src_ip = getattr(packet, "src", "")
    dst_ip = getattr(packet, "dst", "")

    # Additions: try to extract Host/User-Agent/SNI
    website = ""
    browser = ""
    if TCP in packet and hasattr(packet[TCP], "payload") and packet[TCP].payload:
        raw_payload = bytes(packet[TCP].payload)
        # Try HTTP first
        host, user_agent = parse_http_host_useragent(raw_payload)
        if host:
            website = host
        if user_agent:
            browser = user_agent.split("/")[0]  # Show browser family
        # Try SNI for HTTPS
        if not website and packet[TCP].dport == 443:
            sni = parse_tls_sni(raw_payload)
            if sni:
                website = sni
    # Fallback: show destination IP for encrypted traffic
    if not website and dst_ip:
        website = dst_ip

    short_info = ""
    if Ether in packet:
        short_info += f"Ether: {eth.src} → {eth.dst}, "
    if IP in packet:
        ip = packet[IP]
        short_info += f"IP: {ip.src} → {ip.dst}, "
    if TCP in packet:
        tcp = packet[TCP]
        flags = tcp.sprintf("%flags%")
        short_info += f"TCP: {tcp.sport}->{tcp.dport}, flags={flags}, "
    elif UDP in packet:
        udp = packet[UDP]
        short_info += f"UDP: {udp.sport}->{udp.dport}, "
    if website:
        short_info += f"Site: {website}, "
    if browser:
        short_info += f"Browser: {browser}, "
    if not short_info:
        short_info = packet.summary()
    short_info = (short_info[:100] + "...") if len(short_info) > 100 else short_info

    # Add website and browser details to full_info
    info_lines = []
    if Ether in packet:
        info_lines.append(f"Ether: src={eth.src}, dst={eth.dst}, type={hex(eth.type)}")
    if IP in packet:
        ip = packet[IP]
        info_lines.append(f"IP: src={ip.src}, dst={ip.dst}, proto={ip.proto}, version={ip.version}, ttl={ip.ttl}, len={ip.len}, id={ip.id}, flags={ip.flags}")
    if TCP in packet:
        tcp = packet[TCP]
        flags = tcp.sprintf("%flags%")
        info_lines.append(f"TCP: sport={tcp.sport}, dport={tcp.dport}, flags={flags}, seq={tcp.seq}, ack={tcp.ack}, window={tcp.window}")
    elif UDP in packet:
        udp = packet[UDP]
        info_lines.append(f"UDP: sport={udp.sport}, dport={udp.dport}, len={udp.len}")
    if website:
        info_lines.append(f"Website/Host: {website}")
    if browser:
        info_lines.append(f"Browser (User-Agent): {browser}")
    info_lines.append("Packet summary: " + packet.summary())
    try:
        info_lines.append("Raw packet (hex): " + bytes(packet).hex())
    except Exception:
        pass

    full_info = "\n".join(info_lines)
    length = len(packet)
    pkt_time = "%.6f" % packet.time

    # Add website and browser to the table row (optional: expand cols)
    row = (pkt_time, src_mac, src_ip, dst_mac, dst_ip, proto, length, short_info)
    packet_queue.put((row, full_info))

    # For graph
    now = time_mod.time()
    packet_times.append(now)
    if proto:
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

# ... [rest of your code unchanged] ...
def start_sniffing(interface, filter_text):
    if not interface:
        messagebox.showwarning("No Interface", "No valid interface selected.")
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")
        return
    try:
        sniff(prn=packet_callback, iface=interface, store=0,
              stop_filter=lambda x: stop_sniffing.is_set(),
              filter=filter_text if filter_text else None)
    except Exception as e:
        messagebox.showerror("Sniffing Error", str(e))
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")
