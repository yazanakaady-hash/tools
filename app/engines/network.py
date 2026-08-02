"""Network Protocol Reverse Engineer — PCAP analysis (pure Python)."""
from __future__ import annotations

import struct
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse


def _ip_to_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _parse_ethernet(frame: bytes) -> dict | None:
    if len(frame) < 14:
        return None
    dst, src, ethertype = frame[:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
    return {"dst_mac": dst.hex(":"), "src_mac": src.hex(":"), "ethertype": ethertype, "payload": frame[14:]}


def _parse_ipv4(pkt: bytes) -> dict | None:
    if len(pkt) < 20:
        return None
    vihl = pkt[0]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4 or len(pkt) < ihl:
        return None
    total_len = struct.unpack("!H", pkt[2:4])[0]
    proto = pkt[9]
    src = _ip_to_str(pkt[12:16])
    dst = _ip_to_str(pkt[16:20])
    return {"version": 4, "proto": proto, "src": src, "dst": dst, "payload": pkt[ihl:total_len] if total_len else pkt[ihl:]}


def _parse_udp(pkt: bytes) -> dict | None:
    if len(pkt) < 8:
        return None
    sport, dport, length, _c = struct.unpack("!HHHH", pkt[:8])
    return {"sport": sport, "dport": dport, "payload": pkt[8:length] if length >= 8 else pkt[8:]}


def _parse_tcp(pkt: bytes) -> dict | None:
    if len(pkt) < 20:
        return None
    sport, dport = struct.unpack("!HH", pkt[:4])
    data_off = ((pkt[12] >> 4) & 0xF) * 4
    flags = pkt[13]
    return {
        "sport": sport,
        "dport": dport,
        "flags": flags,
        "syn": bool(flags & 0x02),
        "ack": bool(flags & 0x10),
        "fin": bool(flags & 0x01),
        "rst": bool(flags & 0x04),
        "payload": pkt[data_off:],
    }


def _parse_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    start = offset
    guard = 0
    while guard < 64:
        guard += 1
        if offset >= len(payload):
            break
        l = payload[offset]
        if l == 0:
            offset += 1
            break
        if (l & 0xC0) == 0xC0:
            if offset + 1 >= len(payload):
                break
            ptr = struct.unpack("!H", payload[offset : offset + 2])[0] & 0x3FFF
            name, _ = _parse_dns_name(payload, ptr)
            labels.append(name)
            offset += 2
            jumped = True
            break
        offset += 1
        labels.append(payload[offset : offset + l].decode("ascii", errors="replace"))
        offset += l
    return ".".join(labels), (start + 1 if jumped else offset)


def _parse_dns(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    try:
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
        name, off = _parse_dns_name(payload, 12)
        qtype = qclass = 0
        if off + 4 <= len(payload):
            qtype, qclass = struct.unpack("!HH", payload[off : off + 4])
        return {"id": tid, "qr": bool(flags & 0x8000), "questions": qd, "name": name, "qtype": qtype}
    except Exception:
        return None


def _is_private_ip(ip: str) -> bool:
    """RFC1918 (10/8, 172.16/12, 192.168/16) + loopback check."""
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(parts) < 4:
        return False
    a, b = parts[0], parts[1]
    return (
        a == 10
        or (a == 192 and b == 168)
        or (a == 172 and 16 <= b <= 31)
        or a == 127
    )


def _classify_endpoint(ip: str, port: int, host_hint: str | None, dns_names: set[str]) -> str:
    if port in (53,) or host_hint and host_hint in dns_names:
        pass
    known_c2_ports = {4444, 5555, 6666, 6667, 1337, 31337, 8081, 8443, 9001, 9050}
    if port in known_c2_ports:
        return "c2_suspected"
    if port in (80, 8080, 8000):
        return "http"
    if port in (443, 8443):
        return "https"
    if port == 53:
        return "dns"
    if port in (25, 465, 587):
        return "smtp"
    if port in (22,):
        return "ssh"
    if port in (123,):
        return "ntp"
    if host_hint:
        h = host_hint.lower()
        if any(x in h for x in ("update", "download", "cdn", "windows", "microsoft", "google")):
            return "update/cdn"
        if any(x in h for x in ("telegram", "discord", "pastebin", "ngrok", "trycloudflare")):
            return "exfil/channel"
        if any(x in h for x in ("onion", "tor", "i2p")):
            return "c2_suspected"
    if _is_private_ip(ip):
        return "local"
    return "unknown"


def analyze_pcap(data: bytes, max_packets: int = 5000) -> dict[str, Any]:
    """Parse classical pcap (not pcapng) and summarize protocols / destinations."""
    if len(data) < 24:
        return {"ok": False, "error": "file too small"}

    magic = data[:4]
    # pcapng
    if magic == b"\x0a\x0d\x0d\x0a":
        return {"ok": False, "error": "pcapng detected — export as classic pcap (Wireshark: File → Save As → pcap)"}

    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        return {"ok": False, "error": f"not a classic pcap (magic={magic.hex()})"}

    # global header 24 bytes
    ver_maj, ver_min, thisz, sigfigs, snaplen, network = struct.unpack(endian + "HHiiii", data[4:24])
    offset = 24
    packets = []
    dns_names: set[str] = set()
    http_hosts: list[str] = []
    flows = Counter()
    proto_counter = Counter()
    endpoints = Counter()
    suspicious = []

    while offset + 16 <= len(data) and len(packets) < max_packets:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", data[offset : offset + 16])
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        if not frame:
            continue

        info: dict[str, Any] = {"ts": ts_sec + ts_usec / 1e6, "len": incl_len}
        # linktype 1 = ethernet
        payload = frame
        if network == 1:
            eth = _parse_ethernet(frame)
            if not eth:
                continue
            info["ethertype"] = eth["ethertype"]
            payload = eth["payload"]
            if eth["ethertype"] != 0x0800:
                if eth["ethertype"] == 0x86DD:
                    proto_counter["ipv6"] += 1
                continue
        elif network == 101:  # raw IP
            pass
        else:
            # try eth anyway
            eth = _parse_ethernet(frame)
            if eth and eth["ethertype"] == 0x0800:
                payload = eth["payload"]
            else:
                continue

        ip = _parse_ipv4(payload)
        if not ip:
            continue
        proto_counter["ipv4"] += 1
        info["src"] = ip["src"]
        info["dst"] = ip["dst"]
        pl = ip["payload"]

        if ip["proto"] == 6:
            proto_counter["tcp"] += 1
            tcp = _parse_tcp(pl)
            if not tcp:
                continue
            info["proto"] = "tcp"
            info["sport"] = tcp["sport"]
            info["dport"] = tcp["dport"]
            flow = f"{ip['src']}:{tcp['sport']} → {ip['dst']}:{tcp['dport']}"
            flows[flow] += 1
            endpoints[(ip["dst"], tcp["dport"])] += 1
            # HTTP
            body = tcp["payload"]
            if body.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"HTTP/")):
                proto_counter["http"] += 1
                try:
                    text = body.decode("ascii", errors="ignore")
                    host = None
                    for line in text.split("\r\n")[:20]:
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            http_hosts.append(host)
                    info["http_preview"] = text[:120].replace("\r", " ").replace("\n", " ")
                    if host:
                        info["host"] = host
                except Exception:
                    pass
            elif tcp["dport"] == 443 or tcp["sport"] == 443:
                proto_counter["tls"] += 1
                # client hello SNI snip
                sni = _extract_sni(body)
                if sni:
                    info["sni"] = sni
                    http_hosts.append(sni)
        elif ip["proto"] == 17:
            proto_counter["udp"] += 1
            udp = _parse_udp(pl)
            if not udp:
                continue
            info["proto"] = "udp"
            info["sport"] = udp["sport"]
            info["dport"] = udp["dport"]
            flow = f"{ip['src']}:{udp['sport']} → {ip['dst']}:{udp['dport']}"
            flows[flow] += 1
            endpoints[(ip["dst"], udp["dport"])] += 1
            if udp["dport"] == 53 or udp["sport"] == 53:
                proto_counter["dns"] += 1
                dns = _parse_dns(udp["payload"])
                if dns and dns.get("name"):
                    dns_names.add(dns["name"])
                    info["dns"] = dns["name"]
                    # DNS tunneling heuristic
                    labels = dns["name"].split(".")
                    if any(len(l) > 40 for l in labels) or len(dns["name"]) > 80:
                        suspicious.append({"type": "dns_tunneling_suspected", "name": dns["name"]})
        elif ip["proto"] == 1:
            proto_counter["icmp"] += 1
            info["proto"] = "icmp"
        else:
            info["proto"] = f"ip/{ip['proto']}"

        packets.append(info)

    classified = []
    for (ip, port), count in endpoints.most_common(40):
        # find host
        host = None
        classified.append(
            {
                "ip": ip,
                "port": port,
                "packets": count,
                "class": _classify_endpoint(ip, port, host, dns_names),
            }
        )

    # attach hosts when possible via http/sni
    host_set = sorted(set(http_hosts) | dns_names)

    return {
        "ok": True,
        "format": "pcap",
        "endian": "LE" if endian == "<" else "BE",
        "snaplen": snaplen,
        "linktype": network,
        "packet_count": len(packets),
        "protocols": dict(proto_counter),
        "top_flows": [{"flow": f, "count": c} for f, c in flows.most_common(25)],
        "endpoints": classified,
        "dns_names": sorted(dns_names)[:100],
        "http_tls_hosts": host_set[:100],
        "suspicious": suspicious[:50],
        "sample_packets": packets[:30],
        "fingerprint": _network_fingerprint(proto_counter, host_set, classified),
    }


def _extract_sni(data: bytes) -> str | None:
    # very small TLS ClientHello SNI extractor
    try:
        if len(data) < 40 or data[0] != 0x16:
            return None
        # skip to extensions — naive search for SNI type 0x0000
        idx = data.find(b"\x00\x00")
        # better: scan for host_name
        i = 0
        while i < len(data) - 9:
            if data[i : i + 2] == b"\x00\x00":  # extension type server_name
                ext_len = struct.unpack("!H", data[i + 2 : i + 4])[0]
                if i + 4 + ext_len <= len(data) and ext_len > 5:
                    # list length + type + name length
                    j = i + 4
                    if j + 5 <= len(data) and data[j + 2] == 0:  # host_name
                        nlen = struct.unpack("!H", data[j + 3 : j + 5])[0]
                        name = data[j + 5 : j + 5 + nlen]
                        return name.decode("ascii", errors="replace")
            i += 1
    except Exception:
        return None
    return None


def _network_fingerprint(protos: Counter, hosts: list[str], endpoints: list[dict]) -> dict[str, Any]:
    c2 = [e for e in endpoints if e["class"] == "c2_suspected"]
    return {
        "summary": (
            f"Protocols={dict(protos)}; hosts={len(hosts)}; "
            f"C2-suspected endpoints={len(c2)}; "
            f"DNS={'yes' if protos.get('dns') else 'no'}; "
            f"TLS={'yes' if protos.get('tls') else 'no'}"
        ),
        "beaconing_hint": any(e["packets"] > 50 for e in endpoints),
        "c2_candidates": c2[:10],
    }


def summarize_flows(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return result.get("error", "fail")
    return result.get("fingerprint", {}).get("summary", "")
