"""File-backed UI contracts; these tests do not create a Tk window or capture traffic."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from netview.session import Session
from netview.ui import PREVIEW_LIMIT, Inspector, format_size, hex_dump, readable


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "lab_demo.netview.json"


class UIHelpersTests(unittest.TestCase):
    def test_sizes_and_endpoints_distinguish_units_and_ipv6(self):
        self.assertEqual(format_size(42), "42 Б")
        self.assertEqual(format_size(1024), "1.0 КиБ")
        self.assertEqual(format_size(1024 * 1024), "1.0 МиБ")
        self.assertEqual(Inspector.endpoint("::1", 443), "[::1]:443")
        self.assertEqual(Inspector.endpoint("127.0.0.1", None), "127.0.0.1")
        self.assertEqual(Inspector.endpoint("", None), "Неизвестно")

    def test_hex_dump_preserves_offsets_and_hides_nonprintable_bytes(self):
        dump = hex_dump(b"Hello\x00\xff" + b"0123456789")
        self.assertIn("000000", dump)
        self.assertIn("48 65 6c 6c 6f 00 ff", dump)
        self.assertIn("Hello..", dump)
        self.assertIn("000010", dump)
        self.assertEqual(hex_dump(b""), "Нет данных.")
        capped = hex_dump(b"x" * (PREVIEW_LIMIT + 16))
        self.assertEqual(len(capped.splitlines()), PREVIEW_LIMIT // 16)

    def test_tls_and_invalid_utf8_are_not_presented_as_plaintext(self):
        self.assertIn("не расшифровывает", readable(b"\x17\x03\x03\x00\x02\xff\xff"))
        self.assertIn("HEX", readable(b"\xff\xfe\x80"))
        self.assertIn("Бинарные данные", readable(b"\x00\x01"))
        self.assertIn("Нет прикладных данных", readable(b""))

    def test_single_large_stream_explicitly_reports_preview_truncation(self):
        data = b"x" * (PREVIEW_LIMIT + 10)
        viewer = Inspector.__new__(Inspector)
        viewer.selected_connection = 1
        viewer.session = SimpleNamespace(notes=[], stream=lambda _: [{"name": "test", "data": data, "issues": []}])
        viewer.stream_text = object()
        rendered = []
        viewer.set_text = lambda _widget, text: rendered.append(text)
        viewer.render_stream()
        self.assertIn("усечена в просмотре", rendered[0])
        self.assertIn("Полные сохранённые байты", rendered[0])
        self.assertEqual(rendered[0].count("x"), PREVIEW_LIMIT)
        self.assertEqual(len(viewer.session.stream(1)[0]["data"]), PREVIEW_LIMIT + 10)

    def test_json_http_and_lab_frame_have_readable_output(self):
        body = '{"message":"Привет","value":42}'.encode()
        self.assertIn('"message": "Привет"', readable(body))
        http = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body
        text = readable(http)
        self.assertIn("HTTP/1.1 200 OK", text)
        self.assertIn('"value": 42', text)
        framed = len(body).to_bytes(4, "big") + body
        self.assertIn("префикс длины", readable(framed))
        self.assertIn('"message": "Привет"', readable(framed))

    def test_loss_notes_preserve_imported_history_and_replace_current_warning(self):
        viewer = Inspector.__new__(Inspector)
        imported = "Захват неполный: потери очереди 9; потери ядра 2."
        other = "Захват начат посреди соединения."
        viewer.session = SimpleNamespace(notes=[imported, other])
        viewer.loss_note = None
        viewer.dropped = 0
        viewer.kernel_dropped = None
        viewer.dirty = False
        viewer.record_losses()
        self.assertEqual(viewer.session.notes, [imported, other])
        self.assertFalse(viewer.dirty)
        viewer.dropped = 3
        viewer.record_losses()
        first_warning = viewer.loss_note
        self.assertTrue(viewer.dirty)
        self.assertEqual(viewer.session.notes, [imported, other, first_warning])
        self.assertIn("потери очереди 3", first_warning)
        viewer.dropped = 7
        viewer.kernel_dropped = 4
        viewer.record_losses()
        self.assertEqual(viewer.session.notes, [imported, other, viewer.loss_note])
        self.assertNotIn(first_warning, viewer.session.notes)
        self.assertIn("потери очереди 7; потери ядра 4", viewer.loss_note)

    def test_capture_finished_waits_for_worker_before_reenabling_controls(self):
        viewer = Inspector.__new__(Inspector)
        scheduled, states, statuses = [], [], []
        viewer.root = SimpleNamespace(after=lambda delay, callback: scheduled.append((delay, callback)))
        viewer.capture = SimpleNamespace(running=True)
        viewer.stopping = True
        viewer.capture_error = None
        viewer.session = SimpleNamespace(limit_reached=False)
        viewer.status = SimpleNamespace(set=statuses.append)
        for name in ("start_button", "stop_button", "open_button", "save_button", "clear_button"):
            setattr(viewer, name, SimpleNamespace(configure=lambda **kwargs: states.append(kwargs)))
        viewer.capture_finished()
        self.assertEqual(states, [])
        self.assertTrue(viewer.stopping)
        self.assertEqual(len(scheduled), 1)
        viewer.capture.running = False
        scheduled.pop()[1]()
        self.assertFalse(viewer.stopping)
        self.assertEqual(len(states), 5)
        self.assertIn("Захват остановлен", statuses[-1])
        viewer.stopping = True
        viewer.capture_error = "Некорректные данные захвата: поврежденный кадр"
        viewer.capture_finished()
        self.assertEqual(statuses[-1], viewer.capture_error)

    def test_close_keeps_window_until_capture_worker_has_finished(self):
        viewer = Inspector.__new__(Inspector)
        scheduled, destroyed, stopped = [], [], []
        viewer.root = SimpleNamespace(after=lambda delay, callback: scheduled.append((delay, callback)),
                                    destroy=lambda: destroyed.append(True))
        viewer.capture = SimpleNamespace(running=True, stop=lambda: stopped.append(True))
        viewer.controls_busy = False
        viewer.dirty = False
        viewer.status = SimpleNamespace(set=lambda _: None)
        viewer.close()
        self.assertTrue(viewer.closed)
        self.assertEqual(stopped, [True])
        self.assertEqual(destroyed, [])
        self.assertEqual(len(scheduled), 1)
        viewer.capture.running = False
        scheduled.pop()[1]()
        self.assertEqual(destroyed, [True])


class DemoFileContractsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session = Session.load(FIXTURE)

    def test_demo_is_explicitly_synthetic_and_contains_raw_frames(self):
        self.assertEqual(len(self.session.packets), 20)
        self.assertEqual(len(self.session.connections()), 6)
        self.assertTrue(all("SYNTHETIC" in packet["process"] for packet in self.session.packets))
        self.assertTrue(all(packet["raw"] for packet in self.session.packets))
        self.assertEqual({packet["pid"] for packet in self.session.packets}, {424242, None})
        self.assertTrue(any(packet["issues"] for packet in self.session.packets))

    def test_demo_http_reassembles_both_directions_and_keeps_retransmission_evidence(self):
        connection = next(conn for conn in self.session.connections() if conn["dport"] == 18765)
        streams = self.session.stream(connection["id"])
        self.assertEqual(len(streams), 2)
        self.assertTrue(streams[0]["data"].startswith(b"POST /echo HTTP/1.1"))
        self.assertTrue(streams[1]["data"].startswith(b"HTTP/1.1 200 OK"))
        self.assertEqual(streams[0]["data"].split(b"\r\n\r\n", 1)[1], streams[1]["data"].split(b"\r\n\r\n", 1)[1])
        self.assertTrue(any("overlapping" in issue for issue in streams[0]["issues"]))
        self.assertFalse(any("gap" in issue for part in streams for issue in part["issues"]))

    def test_demo_gaps_are_separate_parts_and_udp_remains_datagrams(self):
        gap = next(conn for conn in self.session.connections() if conn["sport"] == 50004)
        parts = self.session.stream(gap["id"])
        self.assertEqual([part["data"] for part in parts], [b"hello", b"world"])
        self.assertTrue(all(any("5 missing" in issue for issue in part["issues"]) for part in parts))
        udp = next(conn for conn in self.session.connections() if conn["protocol"] == "UDP")
        datagrams = self.session.stream(udp["id"])
        self.assertEqual(len(datagrams), 2)
        self.assertEqual(datagrams[0]["data"], datagrams[1]["data"])
        self.assertTrue(all("Datagram" in part["name"] for part in datagrams))

    def test_demo_session_roundtrip_preserves_decoding_streams_and_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "roundtrip.netview.json"
            self.session.save(path)
            loaded = Session.load(path)
        self.assertEqual(loaded.packets, self.session.packets)
        self.assertEqual(loaded.connections(), self.session.connections())
        self.assertEqual(loaded.total_bytes, self.session.total_bytes)
        for connection in self.session.connections():
            self.assertEqual(loaded.stream(connection["id"]), self.session.stream(connection["id"]))


if __name__ == "__main__":
    unittest.main()
