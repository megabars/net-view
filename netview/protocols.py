"""Conservative, dependency-free decoding of common packet capture link types."""

from __future__ import annotations

import ipaddress
import struct

from .models import CapturedFrame


def decode_frame(frame: CapturedFrame) -> dict:
    """Decode what is actually present; retain the original capture on every path."""
    raw = frame.data
    packet = {
        "timestamp": frame.timestamp, "pid": frame.pid, "process": frame.process,
        "effective_pid": frame.effective_pid, "effective_process": frame.effective_process,
        "interface": frame.interface, "direction": frame.direction,
        "src": "", "dst": "", "sport": None, "dport": None,
        "protocol": "Unknown", "summary": "Unknown frame", "payload": b"",
        "raw": raw, "tcp_seq": None, "tcp_flags": 0, "issues": [],
        "wire_length": frame.original_length or len(raw), "linktype": frame.linktype,
    }
    issues = packet["issues"]
    if frame.original_length > len(raw):
        issues.append("Capture truncated: fewer bytes than the original frame")
    offset = 0
    ethertype = None
    if frame.linktype == 1:  # Ethernet, including stacked 802.1Q tags
        if len(raw) < 14:
            issues.append("Truncated Ethernet header")
            return packet
        offset, ethertype = 14, struct.unpack_from("!H", raw, 12)[0]
        for _ in range(4):
            if ethertype not in (0x8100, 0x88A8, 0x9100):
                break
            if len(raw) < offset + 4:
                issues.append("Truncated VLAN header")
                return packet
            ethertype = struct.unpack_from("!H", raw, offset + 2)[0]
            offset += 4
        if ethertype in (0x8100, 0x88A8, 0x9100):
            issues.append("VLAN nesting limit exceeded")
            return packet
        if ethertype == 0x0806:
            packet.update(protocol="ARP", summary="ARP", payload=raw[offset:])
            return packet
    elif frame.linktype in (0, 108):  # DLT_NULL is host order; LOOP is network order
        if len(raw) < 4:
            issues.append("Truncated loopback header")
            return packet
        orders = ("!I",) if frame.linktype == 108 else ("<I", ">I")
        families = [struct.unpack_from(order, raw)[0] for order in orders]
        offset = 4
        if 2 in families:
            ethertype = 0x0800
        elif any(family in (10, 24, 28, 30) for family in families):
            ethertype = 0x86DD
        else:
            issues.append("Unsupported loopback address family")
            return packet
    elif frame.linktype in (12, 101):  # historical RAW / LINKTYPE_RAW
        if raw:
            ethertype = {4: 0x0800, 6: 0x86DD}.get(raw[0] >> 4)
    elif frame.linktype in (228, 229):
        ethertype = 0x0800 if frame.linktype == 228 else 0x86DD
    elif frame.linktype in (113, 276):  # Linux cooked v1 / v2, useful for offline files
        offset = 16 if frame.linktype == 113 else 20
        if len(raw) < offset:
            issues.append("Truncated cooked capture header")
            return packet
        ethertype = struct.unpack_from("!H", raw, 14 if frame.linktype == 113 else 0)[0]
    else:
        issues.append(f"Unsupported link type {frame.linktype}")
        packet["payload"] = raw
        return packet
    if ethertype not in (0x0800, 0x86DD):
        packet["payload"] = raw[offset:]
        packet["summary"] = "Unsupported network protocol"
        issues.append("Unsupported network protocol")
        return packet
    data = raw[offset:]
    if ethertype == 0x0800:
        packet.update(protocol="IPv4", summary="IPv4")
        if len(data) < 20:
            issues.append("Truncated IPv4 header")
            return packet
        ihl = (data[0] & 15) * 4
        total = struct.unpack_from("!H", data, 2)[0]
        if data[0] >> 4 != 4 or ihl < 20 or total < ihl:
            issues.append("Malformed IPv4 header or length")
            return packet
        packet.update(src=str(ipaddress.ip_address(data[12:16])), dst=str(ipaddress.ip_address(data[16:20])))
        if len(data) < ihl:
            issues.append("Truncated IPv4 options")
            return packet
        if len(data) < total:
            issues.append("Truncated IPv4 packet")
        data = data[:total]
        transport = data[ihl:]
        protocol = data[9]
        if struct.unpack_from("!H", data, 6)[0] & 0x3FFF:
            issues.append("IPv4 fragments are not reassembled; transport decoding skipped")
            packet.update(payload=transport, summary="IPv4 fragment (unsupported)")
            return packet
    else:
        packet.update(protocol="IPv6", summary="IPv6")
        if len(data) < 40:
            issues.append("Truncated IPv6 header")
            return packet
        if data[0] >> 4 != 6:
            issues.append("Malformed IPv6 version")
            return packet
        packet.update(src=str(ipaddress.ip_address(data[8:24])), dst=str(ipaddress.ip_address(data[24:40])))
        length = struct.unpack_from("!H", data, 4)[0]
        protocol = data[6]
        if length == 0 and len(data) > 40:
            issues.append("IPv6 jumbograms are unsupported")
            return packet
        if len(data) < 40 + length:
            issues.append("Truncated IPv6 packet")
        data = data[:40 + length]
        cursor = 40
        for _ in range(16):
            if protocol not in (0, 43, 44, 51, 60):
                break
            if protocol == 44:
                issues.append("IPv6 fragments are not reassembled; transport decoding skipped")
                packet.update(payload=data[cursor:], summary="IPv6 fragment (unsupported)")
                return packet
            if cursor + 2 > len(data):
                issues.append("Truncated IPv6 extension header")
                return packet
            extension_length = (data[cursor + 1] + 2) * 4 if protocol == 51 else (data[cursor + 1] + 1) * 8
            if cursor + extension_length > len(data):
                issues.append("Truncated IPv6 extension body")
                return packet
            protocol, cursor = data[cursor], cursor + extension_length
        else:
            issues.append("IPv6 extension traversal limit exceeded")
            return packet
        transport = data[cursor:]
    packet["payload"] = transport
    if protocol == 6:
        packet.update(protocol="TCP", summary="TCP")
        if len(transport) < 20:
            issues.append("Truncated TCP header")
            packet["payload"] = b""
            return packet
        sport, dport, seq = struct.unpack_from("!HHI", transport)
        header_length = (transport[12] >> 4) * 4
        packet.update(sport=sport, dport=dport, tcp_seq=seq, tcp_flags=transport[13])
        if header_length < 20:
            issues.append("Malformed TCP data offset")
            packet["payload"] = b""
            return packet
        if len(transport) < header_length:
            issues.append("Truncated TCP options")
            packet["payload"] = b""
            return packet
        packet["payload"] = transport[header_length:]
        flags = [name for bit, name in ((2, "SYN"), (16, "ACK"), (1, "FIN"), (4, "RST"), (8, "PSH")) if transport[13] & bit]
        packet["summary"] = f"TCP {sport} → {dport} {' '.join(flags)}; {len(packet['payload'])} payload bytes"
        _describe_application(packet)
    elif protocol == 17:
        packet.update(protocol="UDP", summary="UDP")
        if len(transport) < 8:
            issues.append("Truncated UDP header")
            packet["payload"] = b""
            return packet
        sport, dport, length = struct.unpack_from("!HHH", transport)
        packet.update(sport=sport, dport=dport)
        if length < 8:
            issues.append("Malformed or unsupported UDP length")
            packet["payload"] = b""
            return packet
        if len(transport) < length:
            issues.append("Truncated UDP datagram")
        packet["payload"] = transport[8:length]
        packet["summary"] = f"UDP {sport} → {dport}; {len(packet['payload'])} payload bytes"
    elif protocol in (1, 58):
        packet.update(protocol="ICMPv6" if protocol == 58 else "ICMP", summary="ICMPv6" if protocol == 58 else "ICMP")
    elif protocol == 50:
        packet.update(protocol="ESP", summary="ESP (encrypted payload)")
    elif protocol == 59:
        packet["summary"] = "IPv6 no next header"
        packet["payload"] = b""
    else:
        packet["summary"] = f"{packet['protocol']} protocol {protocol} (unsupported)"
    return packet


def _describe_application(packet: dict) -> None:
    payload = packet["payload"]
    if len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4:
        packet["summary"] += "; TLS record (encrypted content is not decrypted)"
        packet["encrypted"] = True
    elif payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/1.")):
        first_line = payload.split(b"\r\n", 1)[0][:200].decode("ascii", "replace")
        packet["summary"] += f"; HTTP {first_line}"
        for line in payload[:8192].split(b"\r\n")[1:]:
            if not line:
                break
            if line.lower().startswith(b"host:"):
                packet["hostname"] = line[5:].strip()[:255].decode("ascii", "replace")
                break
