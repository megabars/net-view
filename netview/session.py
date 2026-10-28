"""Bounded capture storage, connection grouping, and honest stream reconstruction."""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
from pathlib import Path
import tempfile

from .models import CapturedFrame
from .protocols import decode_frame

MAX_PACKETS = 100_000
MAX_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 320 * 1024 * 1024
FORMAT = "netview-session"
VERSION = 1


def _integer(value, name, minimum=0, maximum=2**32 - 1):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"Invalid {name}")
    return value


def _text(value, name, maximum):
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"Invalid {name}")
    return value


def _validated_notes(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("Invalid session notes")
    return [_text(note, "session note", 1024) for note in value]


def _validate_frame(frame):
    if not isinstance(frame, CapturedFrame) or not isinstance(frame.data, bytes):
        raise ValueError("Expected CapturedFrame with bytes data")
    if isinstance(frame.timestamp, bool) or not isinstance(frame.timestamp, (int, float)):
        raise ValueError("Invalid timestamp")
    try:
        finite_timestamp = math.isfinite(frame.timestamp)
    except OverflowError:
        finite_timestamp = False
    if not finite_timestamp:
        raise ValueError("Invalid timestamp")
    _integer(frame.linktype, "linktype")
    _integer(frame.original_length, "original_length")
    for name in ("pid", "effective_pid"):
        if getattr(frame, name) is not None:
            _integer(getattr(frame, name), name, maximum=2**31 - 1)
    for name, maximum in (("process", 256), ("effective_process", 256), ("interface", 128), ("direction", 32)):
        _text(getattr(frame, name), name, maximum)


def _endpoint(address, port):
    address = f"[{address}]" if ":" in address else address or "?"
    return f"{address}:{port}" if port is not None else address


def _direction(packet):
    return (packet["src"], packet["sport"], packet["dst"], packet["dport"])


def _direction_name(packet):
    return f"{_endpoint(packet['src'], packet['sport'])} → {_endpoint(packet['dst'], packet['dport'])}"


class Session:
    def __init__(self, max_packets=10_000, max_bytes=32 * 1024 * 1024):
        self.max_packets = _integer(max_packets, "max_packets", 1, MAX_PACKETS)
        self.max_bytes = _integer(max_bytes, "max_bytes", 1, MAX_BYTES)
        self.packets: list[dict] = []
        self.total_bytes = 0
        self.limit_reached = False
        self.notes: list[str] = []
        self._frames: list[CapturedFrame] = []
        self._connections: dict[int, dict] = {}
        self._active: dict[tuple, int] = {}
        self._connection_packets: dict[int, list[dict]] = {}

    def add(self, frame: CapturedFrame) -> dict | None:
        _validate_frame(frame)
        if self.limit_reached or len(self.packets) >= self.max_packets or self.total_bytes + len(frame.data) > self.max_bytes:
            self.limit_reached = True
            return None
        packet = decode_frame(frame)
        packet["id"] = len(self.packets) + 1
        # PID-less observations remain PID-less. Never attach them by local port.
        endpoints = sorted(((packet["src"], packet["sport"]), (packet["dst"], packet["dport"])), key=lambda item: (item[0], -1 if item[1] is None else item[1]))
        key = (packet["protocol"], tuple(endpoints), packet["pid"], packet["effective_pid"])
        connection_id = self._active.get(key)
        syn = packet["protocol"] == "TCP" and packet["tcp_flags"] & 2 and not packet["tcp_flags"] & 16
        signature = (_direction(packet), packet["tcp_seq"]) if syn else None
        if connection_id is not None and syn:
            existing = self._connections[connection_id]
            prior_packets = self._connection_packets[connection_id]
            missing_syn_after_data = existing["_syn"] is None and any(prior["payload"] or prior["tcp_flags"] & 1 for prior in prior_packets)
            if existing["_closed"] or (existing["_syn"] is not None and existing["_syn"] != signature) or missing_syn_after_data:
                connection_id = None
            elif existing["_syn"] is None:
                # SYN may be delivered after SYN/ACK by the capture adapters.
                existing["_syn"] = signature
        if connection_id is None:
            connection_id = len(self._connections) + 1
            self._active[key] = connection_id
            self._connections[connection_id] = {
                "id": connection_id, "label": _direction_name(packet),
                "protocol": packet["protocol"], "src": packet["src"], "dst": packet["dst"],
                "sport": packet["sport"], "dport": packet["dport"], "pid": packet["pid"],
                "process": packet["process"], "effective_pid": packet["effective_pid"],
                "effective_process": packet["effective_process"],
                "packet_count": 0, "sent_bytes": 0, "received_bytes": 0,
                "_syn": signature, "_closed": False, "_direction": _direction(packet), "_fin_directions": set(),
            }
            self._connection_packets[connection_id] = []
        packet["connection_id"] = connection_id
        connection = self._connections[connection_id]
        connection["packet_count"] += 1
        inbound = packet["direction"].lower() in ("in", "inbound", "incoming", "received")
        outbound = packet["direction"].lower() in ("out", "outbound", "outgoing", "sent")
        counter = "received_bytes" if inbound or (not outbound and _direction(packet) != connection["_direction"]) else "sent_bytes"
        connection[counter] += len(packet["payload"])
        if packet["protocol"] == "TCP":
            if packet["tcp_flags"] & 1:
                connection["_fin_directions"].add(_direction(packet))
            if packet["tcp_flags"] & 4 or len(connection["_fin_directions"]) >= 2:
                connection["_closed"] = True
        self.packets.append(packet)
        self._frames.append(frame)
        self._connection_packets[connection_id].append(packet)
        self.total_bytes += len(frame.data)
        if len(self.packets) == self.max_packets or self.total_bytes == self.max_bytes:
            self.limit_reached = True
        return packet

    def connections(self) -> list[dict]:
        return [{key: value for key, value in connection.items() if not key.startswith("_")} for connection in self._connections.values()]

    def packet(self, packet_id: int) -> dict:
        if isinstance(packet_id, bool) or not isinstance(packet_id, int) or not 1 <= packet_id <= len(self.packets):
            raise KeyError(packet_id)
        return self.packets[packet_id - 1]

    def connection_packets(self, connection_id: int) -> list[dict]:
        return list(self._connection_packets.get(connection_id, ()))

    def stream(self, connection_id: int) -> list[dict]:
        packets = self.connection_packets(connection_id)
        if not packets:
            return []
        if packets[0]["protocol"] == "UDP":
            return [{"name": f"Datagram #{packet['id']}: {_direction_name(packet)}", "data": packet["payload"], "issues": list(packet["issues"])} for packet in packets]
        if packets[0]["protocol"] != "TCP":
            return [{"name": f"Packet #{packet['id']}: {_direction_name(packet)}", "data": packet["payload"], "issues": list(packet["issues"])} for packet in packets]
        directions = {}
        for packet in packets:
            directions.setdefault(_direction(packet), []).append(packet)
        result = []
        for directional_packets in directions.values():
            result.extend(_assemble_tcp(directional_packets))
        return result

    def save(self, path) -> None:
        """Atomically write a versioned .netview.json file with original metadata."""
        destination = Path(path)
        notes = _validated_notes(self.notes)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp", delete=False) as output:
                temporary = output.name
                header = {"format": FORMAT, "version": VERSION, "max_packets": self.max_packets, "max_bytes": self.max_bytes, "limit_reached": self.limit_reached, "notes": notes}
                output.write(json.dumps(header)[:-1] + ', "frames": [')
                for index, frame in enumerate(self._frames):
                    if index:
                        output.write(",")
                    record = dict(vars(frame))
                    record["data"] = base64.b64encode(frame.data).decode("ascii")
                    json.dump(record, output, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
                output.write("]}\n")
            os.replace(temporary, destination)
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    @classmethod
    def load(cls, path) -> Session:
        source = Path(path)
        if source.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("Session file exceeds the safety limit")
        with source.open("rb") as input_file:
            content = input_file.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise ValueError("Session file exceeds the safety limit")
        try:
            document = json.loads(content)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError("Invalid session JSON") from error
        if not isinstance(document, dict) or document.get("format") != FORMAT:
            raise ValueError("Not a Net View session")
        if type(document.get("version")) is not int or document["version"] != VERSION:
            raise ValueError("Unsupported session version")
        session = cls(document.get("max_packets"), document.get("max_bytes"))
        session.notes = _validated_notes(document.get("notes", []))
        frames = document.get("frames")
        limited = document.get("limit_reached", False)
        if not isinstance(limited, bool) or not isinstance(frames, list) or len(frames) > session.max_packets:
            raise ValueError("Invalid session frame count or limit state")
        fields = {"timestamp", "data", "linktype", "original_length", "pid", "process", "effective_pid", "effective_process", "interface", "direction"}
        for record in frames:
            if not isinstance(record, dict) or set(record) != fields:
                raise ValueError("Invalid frame fields")
            encoded = record["data"]
            remaining = session.max_bytes - session.total_bytes
            if not isinstance(encoded, str) or len(encoded) > ((remaining + 2) // 3) * 4:
                raise ValueError("Invalid or oversized frame data")
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError("Invalid frame base64") from error
            if len(data) > remaining:
                raise ValueError("Session exceeds the captured byte limit")
            try:
                frame = CapturedFrame(**dict(record, data=data))
                _validate_frame(frame)
            except (TypeError, ValueError) as error:
                raise ValueError(f"Invalid frame metadata: {error}") from error
            if session.add(frame) is None:
                raise ValueError("Session exceeds its capture limits")
        session.limit_reached = session.limit_reached or limited
        return session


def _assemble_tcp(packets):
    issues = []
    for packet in packets:
        for issue in packet["issues"]:
            if issue not in issues:
                issues.append(issue)
    valid = [packet for packet in packets if packet["tcp_seq"] is not None]
    if not valid:
        return [{"name": _direction_name(packets[0]), "data": b"", "issues": issues + ["No valid TCP sequence numbers"]}]
    syns = [packet for packet in valid if packet["tcp_flags"] & 2]
    if syns:
        anchor = (syns[0]["tcp_seq"] + 1) & 0xFFFFFFFF
    else:
        anchor = valid[0]["tcp_seq"]
        issues.append("Capture started without this direction's SYN; initial bytes may be missing")
    segments = []
    for index, packet in enumerate(valid):
        if not packet["payload"]:
            continue
        start = (packet["tcp_seq"] + bool(packet["tcp_flags"] & 2)) & 0xFFFFFFFF
        relative = ((start - anchor + 0x80000000) & 0xFFFFFFFF) - 0x80000000
        segments.append((relative, index, packet["payload"]))
    segments.sort(key=lambda segment: (segment[0], segment[1]))
    ranges = []
    overlap_count = 0
    conflicting = False
    current = None
    current_start = 0
    expected = 0 if syns else (segments[0][0] if segments else 0)
    for start, _, data in segments:
        if current is None or start > expected:
            if current is not None:
                ranges.append((current_start, bytes(current)))
            if start > expected:
                issues.append(f"TCP gap: {start - expected} missing bytes before relative sequence {start}; parts are not joined")
            current_start, current = start, bytearray(data)
            expected = start + len(data)
            continue
        overlap = min(len(data), expected - start)
        if overlap:
            overlap_count += 1
            # Segments are sorted, so overlap belongs to the current contiguous range.
            existing = current[start - current_start:start - current_start + overlap]
            if existing != data[:overlap]:
                conflicting = True
        if start + len(data) > expected:
            current.extend(data[overlap:])
            expected = start + len(data)
    if current is not None:
        ranges.append((current_start, bytes(current)))
    if overlap_count:
        issues.append(f"{overlap_count} retransmitted/overlapping segments; overlapping bytes counted once")
    if conflicting:
        issues.append("Conflicting overlapping TCP bytes; kept the segment with earlier sequence start (then earlier observation)")
    if not any(packet["tcp_flags"] & (1 | 4) for packet in valid):
        issues.append("No FIN/RST observed in this direction; stream end is not known to be complete")
    # FIN provides evidence of a missing tail even when no later payload arrived.
    for packet in valid:
        if packet["tcp_flags"] & 1:
            fin_sequence = (packet["tcp_seq"] + bool(packet["tcp_flags"] & 2) + len(packet["payload"])) & 0xFFFFFFFF
            fin_relative = ((fin_sequence - anchor + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            if fin_relative > expected:
                issue = f"TCP gap: {fin_relative - expected} missing bytes before FIN"
                if issue not in issues:
                    issues.append(issue)
    name = _direction_name(packets[0])
    if not ranges:
        return [{"name": name, "data": b"", "issues": issues}]
    return [{"name": name if len(ranges) == 1 else f"{name} — part {index + 1} (relative sequence {start})", "data": data, "issues": list(issues)} for index, (start, data) in enumerate(ranges)]
