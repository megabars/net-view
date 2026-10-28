#!/usr/bin/env python3
"""Capture and verify real localhost lab traffic after `sudo -v` in this Terminal.

Writes only this run's synthetic localhost packets and a verification report to
results/. Exit 0 means every scenario was captured and reconstructed in both
application directions with exact body hashes; any missing evidence exits 1.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import queue
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import network_lab
from netview.capture import CaptureService
from netview.session import Session

CLIENT_CODE = """
import json, sys
import network_lab
ports = json.loads(sys.argv[1])
if sys.stdin.readline().strip() != 'go':
    raise SystemExit('Client was not released')
results = [network_lab.exchange(scenario, ports) for scenario in network_lab.SCENARIOS]
print(json.dumps(results, ensure_ascii=False), flush=True)
raise SystemExit(0 if all(result['matched'] for result in results) else 1)
"""


def _body(data: bytes, protocol: str, direction: str) -> bytes:
    """Extract exactly one complete lab application message, never join gaps."""
    if protocol == "HTTP":
        headers, separator, body = data.partition(b"\r\n\r\n")
        if not separator:
            raise ValueError("HTTP headers are incomplete")
        first, *lines = headers.split(b"\r\n")
        if direction == "request" and not first.startswith(b"POST /echo HTTP/1."):
            raise ValueError("HTTP request line missing")
        if direction == "response" and not (first.startswith(b"HTTP/1.") and b" 200 " in first):
            raise ValueError("HTTP 200 response line missing")
        lengths = [line.split(b":", 1)[1].strip() for line in lines
                   if line.lower().startswith(b"content-length:")]
        if len(lengths) != 1:
            raise ValueError("Expected exactly one HTTP Content-Length")
        length = int(lengths[0])
        if length < 0 or length != len(body):
            raise ValueError(f"HTTP body length mismatch: expected {length}, got {len(body)}")
        return body
    if protocol == "TCP":
        if len(data) < 4:
            raise ValueError("TCP application length prefix missing")
        length = struct.unpack_from("!I", data)[0]
        if length != len(data) - 4:
            raise ValueError(f"TCP body length mismatch: expected {length}, got {len(data) - 4}")
        return data[4:]
    return data


def _check_body(data: bytes, result: dict, direction: str) -> dict:
    expected_hash = result["sha256" if direction == "request" else "received_sha256"]
    expected_bytes = result["sent_bytes" if direction == "request" else "received_bytes"]
    body = _body(data, result["protocol"], direction)
    digest = hashlib.sha256(body).hexdigest()
    if len(body) != expected_bytes or digest != expected_hash:
        raise ValueError("Captured application body does not match the client's exact length/SHA-256")
    payload = json.loads(body)
    expected_fields = {"marker": "NET-VIEW-TEST", "scenario": result["scenario"],
                       "request_id": result["request_id"], "client_pid": result["client_pid"]}
    if any(payload.get(key) != value for key, value in expected_fields.items()):
        raise ValueError("Captured JSON does not match the independent client markers")
    return {"passed": True, "body_bytes": len(body), "sha256": digest,
            "expected_sha256": expected_hash}


def verify_session(session: Session, results: list[dict], client_pid: int, ports: dict) -> list[dict]:
    """Use the product's session reassembly, retaining its retransmission/gap notes."""
    checks = []
    for result in results:
        protocol = "http" if result["scenario"].startswith("http") else result["scenario"]
        port = ports[protocol + "_port"]
        scenario = {"scenario": result["scenario"], "protocol": result["protocol"],
                    "client_matched": result["matched"], "directions": {}}
        for direction in ("request", "response"):
            candidates = []
            failures = []
            for connection in session.connections():
                packets = session.connection_packets(connection["id"])
                relevant = [packet for packet in packets
                    if packet["src"] == packet["dst"] == "127.0.0.1"
                    and (packet["sport"] == port or packet["dport"] == port)
                    and (packet["pid"] == client_pid or packet["effective_pid"] == client_pid)]
                if not relevant:
                    continue
                if connection["protocol"] == "UDP":
                    candidates.extend((packet["payload"], packet["issues"], [packet["id"]])
                        for packet in relevant if packet["payload"] and
                        (packet["dport"] == port if direction == "request" else packet["sport"] == port))
                elif connection["protocol"] == "TCP":
                    client_port = next((packet["sport"] if packet["dport"] == port else packet["dport"]
                                        for packet in relevant), None)
                    source, destination = ((client_port, port) if direction == "request"
                                           else (port, client_port))
                    name = f"127.0.0.1:{source} → 127.0.0.1:{destination}"
                    packet_ids = [packet["id"] for packet in relevant
                                  if packet["sport"] == source and packet["dport"] == destination]
                    candidates.extend((part["data"], part["issues"], packet_ids)
                                      for part in session.stream(connection["id"])
                                      if part["name"].startswith(name) and part["data"])
            verified = None
            for data, issues, packet_ids in candidates:
                if any("gap:" in issue.lower() or "conflicting" in issue.lower() for issue in issues):
                    failures.append("TCP gap/conflicting overlap: " + "; ".join(issues))
                    continue
                try:
                    verified = _check_body(data, result, direction)
                    verified.update({"packet_ids": packet_ids, "stream_issues": issues})
                    break
                except (ValueError, TypeError, KeyError) as error:
                    failures.append(str(error))
            scenario["directions"][direction] = verified or {
                "passed": False, "reason": "No complete matching captured message",
                "candidate_errors": sorted(set(failures))[:12], "candidate_count": len(candidates)}
        scenario["passed"] = bool(scenario["client_matched"] and all(
            value["passed"] for value in scenario["directions"].values()))
        checks.append(scenario)
    return checks


def main() -> int:
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    output = ROOT / "results"
    output.mkdir(exist_ok=True)
    session_path = output / f"live-{run_id}.netview.json"
    report_path = output / f"live-{run_id}.report.json"
    session = Session(max_packets=10_000, max_bytes=32 * 1024 * 1024)
    capture = CaptureService()
    server = client = None
    report = {"run_id": run_id, "passed": False, "live_capture_verified": False,
              "session": str(session_path), "scenarios": [], "capture_errors": [],
              "capture_stats": {}, "packet_count": 0}
    failure = None

    def consume(event):
        kind = event["type"]
        if kind == "packet":
            frame = event["frame"]
            if frame.pid != client.pid and frame.effective_pid != client.pid:
                raise RuntimeError("Adapter delivered a packet without the selected PID attribution")
            if session.add(frame) is None:
                raise RuntimeError("Verification session memory/packet limit reached")
        elif kind == "error":
            report["capture_errors"].append(event["message"])
            raise RuntimeError(event["message"])
        elif kind == "stats":
            report["capture_stats"] = {key: value for key, value in event.items() if key != "type"}
        return kind

    try:
        print("Starting synthetic localhost server and paused client…", flush=True)
        server, ports = network_lab.start_child(SimpleNamespace(http_port=0, tcp_port=0, udp_port=0))
        client = subprocess.Popen([sys.executable, "-u", "-c", CLIENT_CODE, json.dumps(ports)],
                                  cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        report.update({"client_pid": client.pid, "server_pid": server.pid, "ports": ports})
        print(f"Waiting for real PID {client.pid} capture (up to 10 seconds)…", flush=True)
        capture.start({client.pid})
        deadline = time.monotonic() + 10
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError("Capture did not become ready within 10 seconds")
            try:
                if consume(capture.events.get(timeout=.1)) == "ready":
                    break
            except queue.Empty:
                if not capture.running:
                    raise RuntimeError("Capture worker stopped before ready")
        client.stdin.write("go\n")
        client.stdin.flush()
        print("Capture ready; exchanging HTTP, large HTTP, TCP and UDP messages…", flush=True)
        deadline = time.monotonic() + 45
        drain_until = None
        while True:
            now = time.monotonic()
            if now >= deadline:
                raise RuntimeError("Client exchanges did not complete within 45 seconds")
            if client.poll() is not None:
                if drain_until is None:
                    drain_until = now + 2.5
                if now >= drain_until:
                    break
            try:
                kind = consume(capture.events.get(timeout=.1))
                if kind == "stopped":
                    raise RuntimeError("Capture ended before exchange drain completed")
            except queue.Empty:
                pass
        client_output, _ = client.communicate(timeout=2)
        if client.returncode != 0:
            raise RuntimeError("Client exchanges failed: " + client_output[:4000])
        results = json.loads(client_output)
        if [item.get("scenario") for item in results] != list(network_lab.SCENARIOS):
            raise RuntimeError("Client did not report all four expected scenarios")
        report["client_results"] = results
    except KeyboardInterrupt:
        failure = "Verification interrupted"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        failure = str(error)
    finally:
        capture.stop()
        deadline = time.monotonic() + 6
        while capture.running or not capture.events.empty():
            if time.monotonic() >= deadline:
                failure = "Capture did not terminate within 6 seconds"
                break
            try:
                consume(capture.events.get(timeout=.1))
            except queue.Empty:
                pass
            except (ValueError, RuntimeError) as error:
                failure = failure or str(error)
        for child in (client, server):
            if child is not None:
                network_lab.stop_child(child)
                if child.stdin:
                    child.stdin.close()
        if not failure and "client_results" in report:
            report["scenarios"] = verify_session(session, report["client_results"], client.pid, ports)
        report["packet_count"] = len(session.packets)
        report["captured_interfaces"] = sorted({packet["interface"] for packet in session.packets})
        report["metadata_directions"] = sorted({packet["direction"] for packet in session.packets})
        report["attributed_pids"] = sorted({packet["pid"] for packet in session.packets if packet["pid"] is not None})
        report["attributed_effective_pids"] = sorted({packet["effective_pid"] for packet in session.packets
                                                    if packet["effective_pid"] is not None})
        drops = report["capture_stats"]
        if drops.get("dropped", 0) or drops.get("kernel_dropped", 0):
            failure = failure or "Capture reported dropped packets"
        if session.limit_reached:
            failure = failure or "Session storage limit reached"
        passed = not failure and len(report["scenarios"]) == 4 and all(item["passed"] for item in report["scenarios"])
        if not passed and not failure:
            failure = "At least one scenario is missing an exact captured request or response"
        report.update({"passed": passed, "live_capture_verified": passed, "failure": failure})
        session.notes.append("Real capture of controlled localhost test traffic; verification run " + run_id)
        if failure:
            session.notes.append(("Verification failed: " + failure)[:1024])
        session.save(session_path)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for scenario in report["scenarios"]:
        directions = ", ".join(f"{name}={'OK' if value['passed'] else 'FAIL'}"
                               for name, value in scenario["directions"].items())
        print(f"{scenario['scenario']}: {directions}")
    print(f"{'PASS' if report['passed'] else 'FAIL'}: {report['packet_count']} captured packets")
    if failure:
        print(failure)
    print(f"Session: {session_path}\nReport:  {report_path}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
