"""Integration checks against real localhost listeners and separate client processes."""

import hashlib
import http.client
import json
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "network_lab.py"


def receive_exact(connection, count):
    chunks = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise AssertionError(f"Connection closed with {remaining} bytes missing")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class NetworkLabIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = subprocess.Popen(
            [sys.executable, str(APP), "server", "--http-port", "0",
             "--tcp-port", "0", "--udp-port", "0"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        cls.addClassCleanup(cls.stop_server)
        ready_lines = queue.Queue()
        threading.Thread(target=lambda: ready_lines.put(cls.server.stdout.readline()), daemon=True).start()
        try:
            line = ready_lines.get(timeout=10)
        except queue.Empty:
            raise AssertionError("Server did not announce readiness within 10 seconds")
        if not line:
            raise AssertionError(f"Server exited before readiness: {cls.server.stderr.read()}")
        cls.ready = json.loads(line)
        if cls.ready.get("ready") is not True:
            raise AssertionError(f"Unexpected readiness message: {cls.ready!r}")
        if cls.ready.get("pid") != cls.server.pid:
            raise AssertionError("Readiness PID must identify the server process")
        for name in ("http_port", "tcp_port", "udp_port"):
            port = cls.ready[name]
            if type(port) is not int or not 1 <= port <= 65535:
                raise AssertionError(f"Invalid assigned port: {name}={port!r}")

    @classmethod
    def stop_server(cls):
        if cls.server.poll() is None:
            cls.server.terminate()
        try:
            cls.server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.communicate(timeout=5)

    def request(self, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.ready["http_port"], timeout=5)
        try:
            connection.request(method, path, body=body)
            response = connection.getresponse()
            return response.status, response.getheader("Content-Type", ""), response.read()
        finally:
            connection.close()

    def test_http_health_identifies_server(self):
        status, content_type, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)
        self.assertEqual(json.loads(body), {"status": "ok", "server_pid": self.server.pid})

    def test_http_browser_page_and_unknown_route(self):
        status, content_type, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn(b"<html", body.lower())
        self.assertEqual(self.request("GET", "/missing-integration-test")[0], 404)

    def test_http_exact_echo_including_empty_and_large_body(self):
        for payload in (b"", "Привет, localhost!\n".encode(), bytes(range(256)) * 513):
            with self.subTest(size=len(payload)):
                status, _, echoed = self.request("POST", "/echo", payload)
                self.assertEqual(status, 200)
                self.assertEqual(echoed, payload)

    def test_tcp_echo_accepts_fragmented_frame(self):
        payload = json.dumps({"message": "Данные по частям", "value": 42}, ensure_ascii=False).encode()
        frame = struct.pack("!I", len(payload)) + payload
        with socket.create_connection(("127.0.0.1", self.ready["tcp_port"]), timeout=5) as connection:
            connection.settimeout(5)
            # Fragment both the length header and the UTF-8 body. No packet-count assumption.
            for fragment in (frame[:1], frame[1:3], frame[3:7], frame[7:12], frame[12:]):
                connection.sendall(fragment)
            self.assertEqual(receive_exact(connection, len(frame)), frame)

    def test_udp_exact_echo(self):
        payload = "UDP: проверка одной датаграммы\n".encode() + b"\x00\xff"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(5)
            connection.sendto(payload, ("127.0.0.1", self.ready["udp_port"]))
            echoed, address = connection.recvfrom(65535)
        self.assertEqual(echoed, payload)
        self.assertEqual(address, ("127.0.0.1", self.ready["udp_port"]))

    def run_client(self, scenario):
        process = subprocess.Popen(
            [sys.executable, str(APP), "client", "--scenario", scenario,
             "--http-port", str(self.ready["http_port"]),
             "--tcp-port", str(self.ready["tcp_port"]),
             "--udp-port", str(self.ready["udp_port"])],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.fail("Client did not complete within 15 seconds")
        self.assertEqual(process.returncode, 0, stderr)
        results = json.loads(stdout)
        self.assertIsInstance(results, list)
        for result in results:
            self.assertEqual(result["client_pid"], process.pid)
            self.assertNotEqual(result["client_pid"], self.server.pid)
            self.assertIs(result["matched"], True)
            self.assertEqual(result["sent_bytes"], result["received_bytes"])
            self.assertGreater(result["sent_bytes"], 0)
            protocol = "http" if result["scenario"].startswith("http") else result["scenario"]
            self.assertEqual(result["protocol"], protocol.upper())
            self.assertEqual(result["address"], f"127.0.0.1:{self.ready[protocol + '_port']}")
            self.assertIsInstance(result["preview"], str)
            self.assertEqual(len(result["sha256"]), hashlib.sha256().digest_size * 2)
            int(result["sha256"], 16)
        return process.pid, results

    def test_cli_all_scenarios_and_separate_client_pids(self):
        first_pid, results = self.run_client("all")
        self.assertCountEqual([item["scenario"] for item in results], ["http", "http-large", "tcp", "udp"])
        large = next(item for item in results if item["scenario"] == "http-large")
        self.assertGreaterEqual(large["sent_bytes"], 65536)
        second_pid, second_results = self.run_client("http")
        self.assertNotEqual(first_pid, second_pid)
        self.assertEqual([item["scenario"] for item in second_results], ["http"])

    def test_cli_individual_scenarios(self):
        for scenario in ("http-large", "tcp", "udp"):
            with self.subTest(scenario=scenario):
                _, results = self.run_client(scenario)
                self.assertEqual([item["scenario"] for item in results], [scenario])


if __name__ == "__main__":
    unittest.main()
