import socket
import struct
import unittest

from netview.models import CapturedFrame
from netview.protocols import decode_frame


def tcp(payload=b"hello", seq=100, flags=0x18, sport=12000, dport=80):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload


def udp(payload=b"hello", sport=12000, dport=53):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(transport, protocol=6, fragment=0):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, fragment, 64, protocol, 0, socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.2")) + transport


def ipv6(transport, protocol=6):
    return struct.pack("!IHBB16s16s", 6 << 28, len(transport), protocol, 64, socket.inet_pton(socket.AF_INET6, "::1"), socket.inet_pton(socket.AF_INET6, "2001:db8::1")) + transport


class ProtocolTests(unittest.TestCase):
    def test_ethernet_ipv4_tcp_metadata_http(self):
        body = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        raw = bytes(12) + b"\x08\x00" + ipv4(tcp(body))
        frame = CapturedFrame(1.5, raw, 1, len(raw), 123, "Client", 456, "Helper", "lo0", "out")
        packet = decode_frame(frame)
        self.assertEqual((packet["protocol"], packet["src"], packet["dst"]), ("TCP", "127.0.0.1", "127.0.0.2"))
        self.assertEqual((packet["sport"], packet["dport"], packet["tcp_seq"]), (12000, 80, 100))
        self.assertEqual(packet["hostname"], "example.test")
        self.assertEqual(packet["payload"], body)
        self.assertEqual(packet["raw"], raw)
        self.assertEqual(packet["effective_process"], "Helper")
        self.assertEqual(packet["issues"], [])

    def test_ipv6_udp_with_hop_extension(self):
        extension = bytes((17, 0)) + bytes(6)
        payload = b"\x00\xffdatagram"
        packet = decode_frame(CapturedFrame(0, ipv6(extension + udp(payload), 0), 101))
        self.assertEqual((packet["protocol"], packet["src"], packet["dst"]), ("UDP", "::1", "2001:db8::1"))
        self.assertEqual(packet["payload"], payload)
        self.assertEqual(packet["issues"], [])

    def test_supported_loopback_and_raw_encodings(self):
        for linktype, header, body in ((0, struct.pack("<I", 2), ipv4(tcp())), (0, struct.pack(">I", 30), ipv6(tcp())), (108, struct.pack("!I", 24), ipv6(tcp())), (12, b"", ipv4(tcp())), (228, b"", ipv4(tcp())), (229, b"", ipv6(tcp()))):
            with self.subTest(linktype=linktype, header=header):
                self.assertEqual(decode_frame(CapturedFrame(0, header + body, linktype))["payload"], b"hello")

    def test_vlan_and_padding_not_in_payload(self):
        raw = bytes(12) + b"\x81\x00" + b"\x00\x01\x08\x00" + ipv4(udp(b"x"), 17) + b"padding"
        self.assertEqual(decode_frame(CapturedFrame(0, raw, 1))["payload"], b"x")

    def test_fragments_never_parse_ports(self):
        for body, linktype in ((ipv4(tcp(), fragment=0x2000), 228), (ipv4(tcp(), fragment=1), 228), (ipv6(bytes((6, 0)) + bytes(6) + tcp(), 44), 229)):
            packet = decode_frame(CapturedFrame(0, body, linktype))
            self.assertIsNone(packet["sport"])
            self.assertTrue(any("fragment" in issue for issue in packet["issues"]))

    def test_truncated_and_malformed_never_crash(self):
        full = bytes(12) + b"\x08\x00" + ipv4(tcp())
        for length in range(len(full)):
            packet = decode_frame(CapturedFrame(0, full[:length], 1, len(full)))
            self.assertTrue(packet["issues"])
            self.assertEqual(packet["raw"], full[:length])
        packet = decode_frame(CapturedFrame(0, ipv4(bytes(20)), 228))
        self.assertIn("Malformed TCP data offset", packet["issues"])
        bad_udp = struct.pack("!HHHH", 1, 2, 7, 0)
        self.assertEqual(decode_frame(CapturedFrame(0, ipv4(bad_udp, 17), 228))["payload"], b"")

    def test_ipv6_extension_bound_and_truncation(self):
        for body in (ipv6(b"\x06", 0), ipv6(bytes((0, 0)) + bytes(6), 0), ipv6((bytes((0, 0)) + bytes(6)) * 17, 0)):
            packet = decode_frame(CapturedFrame(0, body, 229))
            self.assertIsNone(packet["sport"])
            self.assertTrue(packet["issues"])

    def test_tls_and_unsupported_link_preserve_data(self):
        payload = b"\x17\x03\x03\x00\x03abc"
        packet = decode_frame(CapturedFrame(0, ipv4(tcp(payload)), 228))
        self.assertTrue(packet["encrypted"])
        self.assertEqual(packet["payload"], payload)
        raw = b"unknown bytes"
        unknown = decode_frame(CapturedFrame(0, raw, 9999))
        self.assertEqual((unknown["raw"], unknown["payload"]), (raw, raw))


if __name__ == "__main__":
    unittest.main()
