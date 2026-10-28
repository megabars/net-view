#!/usr/bin/env python3
"""Export deterministic Python reference fixtures, or check a Java-written v1 file."""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import shutil
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from netview.models import CapturedFrame
from netview.session import Session

DEST = ROOT / "src/test/resources/parity"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def issue_kinds(issues):
    kinds = []
    for issue in issues:
        text = issue.lower()
        if "gap" in text:
            kind = "gap"
        elif "conflict" in text:
            kind = "conflict"
        elif "overlap" in text or "retransmit" in text:
            kind = "overlap"
        elif "without" in text and "syn" in text:
            kind = "missing-syn"
        elif "fin/rst" in text or "stream end" in text:
            kind = "unknown-end"
        elif "truncat" in text:
            kind = "truncated"
        elif "fragment" in text:
            kind = "fragment"
        elif "malformed" in text:
            kind = "malformed"
        elif "unsupported" in text:
            kind = "unsupported"
        elif "limit" in text:
            kind = "limit"
        else:
            kind = "other"
        kinds.append(kind)
    return kinds


def manifest(session):
    packets = []
    for packet, frame in zip(session.packets, session._frames):
        fields = ("id", "connection_id", "src", "dst", "sport", "dport", "protocol", "tcp_seq", "tcp_flags", "wire_length")
        item = {key: packet[key] for key in fields}
        item.update(payload_length=len(packet["payload"]), payload_sha256=sha(packet["payload"]),
                    raw_sha256=sha(frame.data), captured_length=len(frame.data),
                    issue_count=len(packet["issues"]), issue_kinds=issue_kinds(packet["issues"]))
        item["frame"] = {key: value for key, value in vars(frame).items() if key != "data"}
        packets.append(item)
    streams = []
    for connection in session.connections():
        for stream in session.stream(connection["id"]):
            streams.append(dict(connection_id=connection["id"], name=stream["name"],
                                length=len(stream["data"]), sha256=sha(stream["data"]),
                                issue_count=len(stream["issues"]), issue_kinds=issue_kinds(stream["issues"])))
    return dict(packet_count=len(packets), connection_count=len(session.connections()),
                total_bytes=session.total_bytes, max_packets=session.max_packets, max_bytes=session.max_bytes,
                limit_reached=session.limit_reached, notes=session.notes,
                packets=packets, connections=session.connections(), streams=streams)


def frame(payload=b"", seq=100, flags=0x18, port=10000, reverse=False, udp=False, ipv6=False,
          pid=55, linktype=228):
    src, dst = ("2001:db8::1", "2001:db8::2") if ipv6 else ("127.0.0.1", "127.0.0.2")
    sport, dport = port, 80
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    transport = (struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) if udp else
                 struct.pack("!HHIIBBHHH", sport, dport, seq & 0xffffffff, 0, 0x50, flags, 65535, 0, 0)) + payload
    if ipv6:
        raw = struct.pack("!IHBB16s16s", 6 << 28, len(transport), 17 if udp else 6, 64,
                          ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed) + transport
        linktype = 229
    else:
        raw = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64,
                          17 if udp else 6, 0, ipaddress.ip_address(src).packed,
                          ipaddress.ip_address(dst).packed) + transport
    if linktype == 0:
        raw = struct.pack("<I", 2) + raw
    elif linktype == 1:
        raw = bytes(12) + b"\x08\x00" + raw
    elif linktype == 113:
        raw = bytes(14) + b"\x08\x00" + raw
    elif linktype == 276:
        raw = b"\x08\x00" + bytes(18) + raw
    return CapturedFrame(1700000000.125, raw, linktype, len(raw), pid,
                         "SYNTHETIC PARITY — NOT LIVE", 66, "synthetic effective", "lo0",
                         "in" if reverse else "out")


def stress_session():
    session = Session()
    session.notes.append("SYNTHETIC PARITY — NOT LIVE: deterministic reordered, overlapping, gapped, wrapped and malformed packets")
    def add(value):
        session.add(replace(value, timestamp=1700000000.125 + len(session.packets) / 128))
    # A large binary stream exceeds a GUI preview; arrival order differs from sequence order.
    body = bytes(range(256)) * 512 + "Привет parity".encode()
    add(frame(seq=4000, flags=2, port=11000))
    chunks = [(offset, body[offset:offset + 2048]) for offset in range(0, len(body), 2048)]
    random.Random(1729).shuffle(chunks)
    for offset, data in chunks:
        add(frame(data, seq=4001 + offset, port=11000))
    add(frame(body[:4096], seq=4001, port=11000))
    add(frame(body[2000:4200], seq=6001, port=11000))
    add(frame(seq=4001 + len(body), flags=17, port=11000))
    add(frame(b"response\x00\xff", seq=800, reverse=True, port=11000))
    # Missing prefix, internal gap, missing tail, and conflicting overlap.
    for value in (frame(seq=100, flags=2, port=12000), frame(b"one", seq=104, port=12000),
                  frame(b"two", seq=111, port=12000), frame(seq=120, flags=17, port=12000),
                  frame(b"abc", seq=10, port=12001), frame(b"XYZ", seq=11, port=12001)):
        add(value)
    # 32-bit wrap, SYN/ACK before SYN, closed tuple reuse, duplicate SYN, PID isolation.
    for value in (frame(seq=0xfffffffc, flags=2, port=13000), frame(b"def", seq=0, port=13000),
                  frame(b"abcd", seq=0xfffffffd, port=13000), frame(seq=3, flags=17, port=13000),
                  frame(seq=500, flags=18, reverse=True, port=13001), frame(seq=100, flags=2, port=13001),
                  frame(seq=101, flags=17, port=13001), frame(seq=501, flags=17, reverse=True, port=13001),
                  frame(seq=100, flags=2, port=13001), frame(seq=100, flags=2, port=13001),
                  frame(b"unknown owner", port=13001, pid=None), frame(b"other owner", port=13001, pid=999)):
        add(value)
    for value in (frame(b"\x00\xffudp", port=14000, udp=True), frame(b"second", port=14000, udp=True),
                  frame(b"reverse", port=14000, udp=True, reverse=True),
                  frame(seq=100, flags=2, port=14001, ipv6=True),
                  frame(b"IPv6 payload", seq=101, port=14001, ipv6=True),
                  frame(b"IPv6 UDP", port=14002, udp=True, ipv6=True)):
        add(value)
    for linktype in (0, 1, 12, 101, 108, 113, 276):
        value = frame(b"linktype", port=15000 + linktype, udp=True, linktype=0 if linktype == 108 else linktype)
        if linktype == 108:
            value = replace(value, data=struct.pack("!I", 2) + value.data[4:], linktype=108)
        add(value)
    # These are deliberately invalid frames, not claimed complete protocol coverage.
    add(replace(frame(b"cut payload", port=16000), data=frame(b"cut payload", port=16000).data[:-5]))
    add(CapturedFrame(0, b"\x00\x01\x02", 1, 64, None, "synthetic truncated", None, "", "", "unknown"))
    add(CapturedFrame(0, b"opaque\x00\xff", 999, 0, None, "synthetic unknown", None, "", "", "unknown"))
    fragment = bytearray(frame(b"fragment", port=16001).data)
    fragment[6:8] = b"\x20\x00"
    add(replace(frame(port=16001), data=bytes(fragment), original_length=len(fragment)))
    return session


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-java-output", type=Path)
    parser.add_argument("--expected", type=Path)
    args = parser.parse_args()
    if args.verify_java_output:
        if args.expected is None:
            parser.error("--expected is required with --verify-java-output")
        actual = manifest(Session.load(args.verify_java_output))
        expected = json.loads(args.expected.read_text())["expected"]
        if actual != expected:
            for key in expected:
                if actual.get(key) != expected[key]:
                    raise SystemExit(f"Python reading Java output differs in {key}")
        print(f"Python verified Java output: {len(actual['packets'])} packets, {actual['connection_count']} connections, {actual['total_bytes']} captured bytes")
        return
    DEST.mkdir(parents=True, exist_ok=True)
    real_source = ROOT / "results/live-20261028-201526-2bad5b1b.netview.json"
    if not real_source.is_file():
        # A fresh checkout includes the controlled fixture, not local capture results.
        real_source = DEST / "real-lab.netview.json"
    sources = {
        "synthetic-demo": (ROOT / "tests/fixtures/lab_demo.netview.json", "Synthetic demo; no live capture."),
        "real-lab": (real_source, "Existing real macOS loopback capture of controlled network_lab traffic, captured by Python on 2026-10-28. This fixture does not prove a new Java live capture."),
    }
    stress_session().save(DEST / "synthetic-stress.netview.json")
    descriptions = {"synthetic-stress": "Generated synthetic stress session; no live capture. Fixed binary data and seeded permutation."}
    for name, (source, description) in sources.items():
        destination = DEST / f"{name}.netview.json"
        if source.resolve() != destination.resolve():
            shutil.copyfile(source, destination)
        descriptions[name] = description
    for name, description in sorted(descriptions.items()):
        source = DEST / f"{name}.netview.json"
        expected = manifest(Session.load(source))
        document = dict(reference="Python netview.session.Session", provenance=description,
                        source_sha256=sha(source.read_bytes()), expected=expected)
        (DEST / f"{name}.expected.json").write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
        print(f"{name}: {expected['packet_count']} packets, {expected['connection_count']} connections, {expected['total_bytes']} captured bytes")


if __name__ == "__main__":
    main()
