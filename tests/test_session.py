import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from netview.models import CapturedFrame
from netview.session import Session


def frame(payload=b"", seq=100, flags=0x18, reverse=False, pid=55, udp=False):
    source, destination = ("127.0.0.1", "127.0.0.2") if not reverse else ("127.0.0.2", "127.0.0.1")
    sport, dport = (10000, 80) if not reverse else (80, 10000)
    if udp:
        transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    else:
        transport = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload
    raw = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, 17 if udp else 6, 0, socket.inet_aton(source), socket.inet_aton(destination)) + transport
    return CapturedFrame(1234.5, raw, 228, len(raw), pid, "test", 66, "effective", "lo0", "in" if reverse else "out")


class SessionTests(unittest.TestCase):
    def test_out_of_order_retransmission_and_reverse_direction(self):
        session = Session()
        session.add(frame(seq=100, flags=2))
        session.add(frame(b"world", seq=106))
        session.add(frame(b"hello", seq=101))
        session.add(frame(b"hello", seq=101))
        session.add(frame(seq=111, flags=17))
        session.add(frame(b"response", seq=500, reverse=True))
        self.assertEqual(len(session.connections()), 1)
        connection = session.connections()[0]
        self.assertEqual((connection["packet_count"], connection["sent_bytes"], connection["received_bytes"]), (6, 15, 8))
        streams = session.stream(1)
        self.assertEqual([stream["data"] for stream in streams], [b"helloworld", b"response"])
        self.assertTrue(any("overlapping" in issue for issue in streams[0]["issues"]))
        self.assertFalse(any("gap" in issue for issue in streams[0]["issues"]))
        self.assertEqual(session.packet(3)["payload"], b"hello")
        self.assertEqual(len(session.connection_packets(1)), 6)

    def test_gaps_are_separate_parts_and_missing_prefix_and_tail_reported(self):
        session = Session()
        session.add(frame(seq=100, flags=2))
        session.add(frame(b"one", seq=104))
        session.add(frame(b"two", seq=111))
        session.add(frame(seq=120, flags=17))
        streams = session.stream(1)
        self.assertEqual([stream["data"] for stream in streams], [b"one", b"two"])
        self.assertTrue(any("3 missing" in issue for issue in streams[0]["issues"]))
        self.assertTrue(any("4 missing" in issue for issue in streams[0]["issues"]))
        self.assertTrue(any("6 missing bytes before FIN" in issue for issue in streams[0]["issues"]))

    def test_wrap_and_partial_overlap(self):
        session = Session()
        session.add(frame(seq=0xFFFFFFFC, flags=2))
        session.add(frame(b"def", seq=0))
        session.add(frame(b"abcd", seq=0xFFFFFFFD))
        stream = session.stream(1)[0]
        self.assertEqual(stream["data"], b"abcdef")
        self.assertFalse(any("gap" in issue for issue in stream["issues"]))

    def test_conflict_and_midstream_are_explicit(self):
        session = Session()
        session.add(frame(b"abc", seq=10))
        session.add(frame(b"XYZ", seq=11))
        stream = session.stream(1)[0]
        self.assertEqual(stream["data"], b"abcZ")
        self.assertTrue(any("Conflicting" in issue for issue in stream["issues"]))
        self.assertTrue(any("without" in issue for issue in stream["issues"]))
        self.assertTrue(any("end" in issue for issue in stream["issues"]))

    def test_new_syn_reused_ports_and_pid_isolation(self):
        session = Session()
        session.add(frame(seq=1, flags=2))
        session.add(frame(seq=1, flags=2))
        session.add(frame(b"x", seq=2))
        session.add(frame(seq=100, flags=2))
        session.add(frame(b"unknown", pid=None))
        session.add(frame(b"other", pid=999))
        self.assertEqual([connection["packet_count"] for connection in session.connections()], [3, 1, 1, 1])
        self.assertIsNone(session.connections()[2]["pid"])

    def test_out_of_order_syn_and_closed_tuple_reuse(self):
        session = Session()
        session.add(frame(seq=500, flags=18, reverse=True))
        session.add(frame(seq=100, flags=2))
        self.assertEqual(len(session.connections()), 1)
        session.add(frame(seq=101, flags=17))
        session.add(frame(seq=501, flags=17, reverse=True))
        session.add(frame(seq=100, flags=2))
        self.assertEqual([connection["packet_count"] for connection in session.connections()], [4, 1])

    def test_udp_datagrams_stay_separate(self):
        session = Session()
        session.add(frame(b"a", udp=True))
        session.add(frame(b"b", udp=True))
        streams = session.stream(1)
        self.assertEqual([stream["data"] for stream in streams], [b"a", b"b"])
        self.assertTrue(all("Datagram" in stream["name"] for stream in streams))

    def test_packet_and_byte_limits(self):
        packet_session = Session(max_packets=2)
        self.assertIsNotNone(packet_session.add(frame(b"a")))
        self.assertIsNotNone(packet_session.add(frame(b"b")))
        self.assertTrue(packet_session.limit_reached)
        self.assertIsNone(packet_session.add(frame(b"c")))
        byte_session = Session(max_bytes=len(frame(b"a").data))
        byte_session.add(frame(b"a"))
        self.assertTrue(byte_session.limit_reached)
        self.assertEqual(byte_session.total_bytes, len(frame(b"a").data))
        self.assertIsNone(byte_session.add(frame()))
        oversized = Session(max_bytes=1)
        self.assertIsNone(oversized.add(frame()))
        self.assertEqual(oversized.total_bytes, 0)
        self.assertTrue(oversized.limit_reached)
        for kwargs in ({"max_packets": True}, {"max_bytes": -1}, {"max_packets": 10**12}):
            with self.assertRaises(ValueError):
                Session(**kwargs)
        with self.assertRaises(KeyError):
            packet_session.packet(0)

    def test_save_load_keeps_original_metadata_bytes_and_limits(self):
        session = Session(max_packets=3)
        originals = [frame(seq=1, flags=2), frame(b"\x00\xffpayload", seq=2), frame(b"answer", seq=10, reverse=True)]
        for original in originals:
            session.add(original)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.netview.json"
            session.save(path)
            loaded = Session.load(path)
        self.assertEqual(loaded._frames, originals)
        self.assertEqual(loaded.packets, session.packets)
        self.assertEqual(loaded.connections(), session.connections())
        self.assertEqual(loaded.stream(1), session.stream(1))
        self.assertEqual(loaded.total_bytes, session.total_bytes)
        self.assertTrue(loaded.limit_reached)
        self.assertIsNone(loaded.add(frame()))

    def test_loss_notes_survive_roundtrip_and_old_files_are_supported(self):
        session = Session()
        session.notes.append("Capture queue dropped 12 frames; session is incomplete")
        session.add(frame(b"payload"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.netview.json"
            session.save(path)
            self.assertEqual(Session.load(path).notes, session.notes)
            document = json.loads(path.read_text())
            del document["notes"]
            path.write_text(json.dumps(document))
            self.assertEqual(Session.load(path).notes, [])
            for bad_notes in ("lost", ["x" * 1025], ["x"] * 65, [None]):
                document["notes"] = bad_notes
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    Session.load(path)
            session.notes = ["x"] * 65
            with self.assertRaises(ValueError):
                session.save(path)

    def test_load_rejects_invalid_metadata_base64_and_cap_bypasses(self):
        session = Session()
        session.add(frame(b"payload"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.netview.json"
            session.save(path)
            original = json.loads(path.read_text())
            for mutation in (lambda doc: doc.update(version=True), lambda doc: doc.update(version=1.0), lambda doc: doc.update(max_packets=10**12), lambda doc: doc.update(max_bytes=1), lambda doc: doc.update(limit_reached="yes"), lambda doc: doc["frames"][0].update(data="!invalid!"), lambda doc: doc["frames"][0].update(pid=True), lambda doc: doc["frames"][0].update(timestamp=float("nan")), lambda doc: doc["frames"][0].update(process="x" * 257)):
                document = json.loads(json.dumps(original))
                mutation(document)
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    Session.load(path)
            path.write_text('{"format":')
            with self.assertRaises(ValueError):
                Session.load(path)


if __name__ == "__main__":
    unittest.main()
