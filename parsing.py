from globals import *

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