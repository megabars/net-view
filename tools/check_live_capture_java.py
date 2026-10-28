#!/usr/bin/env python3
"""Verify Java's real capture against independent localhost lab body hashes.

Run scripts/check-live-java.sh in Terminal. Only tcpdump receives elevated
privileges; this verifier, the Java inspector, and the lab stay normal-user.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import network_lab
from netview.session import Session
from check_live_capture import CLIENT_CODE, verify_session


class OutputPump:
    """Drain all child output incrementally so neither stdout nor stderr can stall."""
    def __init__(self, capture, client, report):
        self.selector = selectors.DefaultSelector()
        self.report = report
        self.ready = False
        self.stopped = None
        self.java_pending = bytearray()
        self.client_output = bytearray()
        self.stderr_tail = bytearray()
        for stream, name in ((capture.stdout, "java"), (capture.stderr, "stderr"),
                             (client.stdout, "client")):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def event(self, raw):
        event = json.loads(raw)
        kind = event.get("type")
        if kind == "ready":
            if self.ready:
                raise RuntimeError("Java reported capture readiness more than once")
            self.ready = True
        elif kind == "stopped":
            if self.stopped is not None:
                raise RuntimeError("Java reported more than one final capture result")
            self.stopped = event
            self.report["capture_stats"] = {
                "dropped": event.get("dropped"), "kernel_dropped": event.get("kernel_dropped")}
            if event.get("error"):
                self.report["capture_errors"].append(event["error"])
        elif kind == "error":
            self.report["capture_errors"].append(str(event.get("message", "Unknown Java capture error")))
        else:
            raise RuntimeError("Unexpected Java capture output: " + str(kind))

    def poll(self, timeout=.1):
        for key, _ in self.selector.select(timeout):
            try:
                chunk = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                self.selector.unregister(key.fileobj)
                if key.data == "java" and self.java_pending:
                    self.event(bytes(self.java_pending))
                    self.java_pending.clear()
                continue
            if key.data == "stderr":
                self.stderr_tail.extend(chunk)
                del self.stderr_tail[:-16384]
            elif key.data == "client":
                self.client_output.extend(chunk)
                if len(self.client_output) > 1024 * 1024:
                    raise RuntimeError("Lab client output exceeded its safety limit")
            else:
                self.java_pending.extend(chunk)
                if len(self.java_pending) > 1024 * 1024:
                    raise RuntimeError("Java capture output exceeded its safety limit")
                while b"\n" in self.java_pending:
                    raw, _, rest = self.java_pending.partition(b"\n")
                    self.java_pending[:] = rest
                    if raw.strip():
                        self.event(raw)

    def close(self):
        self.selector.close()


def _stop_capture(capture):
    if capture is not None and capture.poll() is None:
        capture.terminate()  # The Java shutdown hook closes/reaps its tcpdump child.
        try:
            capture.wait(timeout=7)
        except subprocess.TimeoutExpired:
            capture.kill()
            capture.wait(timeout=2)


def _java_inspect(path):
    result = subprocess.run([str(ROOT / "scripts/run.sh"), "--inspect", str(path)],
                            cwd=ROOT, capture_output=True, timeout=20, text=True, encoding="utf-8")
    if result.returncode:
        raise RuntimeError("Java could not reopen its saved session: " + (result.stdout + result.stderr)[-4000:])
    return json.loads(result.stdout)


def _stream_hashes(session):
    streams = {}
    for connection in session.connections():
        for index, part in enumerate(session.stream(connection["id"])):
            streams[f"{connection['id']}:{index}:{part['name']}"] = {
                "bytes": len(part["data"]), "sha256": hashlib.sha256(part["data"]).hexdigest()}
    return streams


def main() -> int:
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    directory = ROOT / "results"
    directory.mkdir(exist_ok=True)
    session_path = directory / f"java-live-{run_id}.netview.json"
    report_path = directory / f"java-live-{run_id}.report.json"
    report = {"engine": "Java", "run_id": run_id, "passed": False,
              "live_capture_verified": False, "session": str(session_path),
              "scenarios": [], "capture_errors": [], "capture_stats": {}, "packet_count": 0}
    server = client = capture = pump = None
    failure = None
    try:
        print("Starting synthetic localhost server and paused client…", flush=True)
        server, ports = network_lab.start_child(SimpleNamespace(http_port=0, tcp_port=0, udp_port=0))
        client = subprocess.Popen([sys.executable, "-u", "-c", CLIENT_CODE, json.dumps(ports)],
                                  cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        report.update({"client_pid": client.pid, "server_pid": server.pid, "ports": ports})
        command = [str(ROOT / "scripts/run.sh"), "--capture", "--pid", str(client.pid),
                   "--seconds", "10", "--output", str(session_path)]
        capture = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        report["capture_command"] = command
        pump = OutputPump(capture, client, report)
        print(f"Waiting for Java capture of real PID {client.pid}…", flush=True)
        deadline = time.monotonic() + 15
        while not pump.ready:
            pump.poll()
            if report["capture_errors"]:
                raise RuntimeError(report["capture_errors"][-1])
            if pump.stopped is not None or capture.poll() is not None:
                # Drain already-written diagnostics before reporting early exit.
                pump.poll(0)
                raise RuntimeError("Java capture stopped before actual readiness")
            if time.monotonic() >= deadline:
                raise RuntimeError("Java did not report capture readiness within 15 seconds")
        client.stdin.write(b"go\n")
        client.stdin.flush()
        client.stdin.close()
        print("Java capture ready; exchanging HTTP, large HTTP, TCP and UDP messages…", flush=True)
        deadline = time.monotonic() + 25
        client_done_at = None
        while capture.poll() is None or pump.selector.get_map():
            pump.poll()
            now = time.monotonic()
            if client.poll() is not None and client_done_at is None:
                client_done_at = now
            if pump.stopped is not None and (client_done_at is None or now - client_done_at < 2.5):
                raise RuntimeError("Java capture stopped before client exchange drain completed")
            if report["capture_errors"]:
                raise RuntimeError(report["capture_errors"][-1])
            if now >= deadline:
                raise RuntimeError("Java capture/client did not finish within 25 seconds")
        if capture.returncode != 0:
            raise RuntimeError(f"Java capture exited with status {capture.returncode}")
        if pump.stopped is None or not pump.stopped.get("ready"):
            raise RuntimeError("Java capture did not report a complete stopped result")
        if client.poll() is None or client.returncode != 0:
            raise RuntimeError("Lab client exchanges failed: " + pump.client_output.decode("utf-8", "replace")[-4000:])
        results = json.loads(pump.client_output)
        if [item.get("scenario") for item in results] != list(network_lab.SCENARIOS):
            raise RuntimeError("Client did not report all four expected scenarios")
        report["client_results"] = results
        session = Session.load(session_path)
        report["packet_count"] = len(session.packets)
        report["raw_bytes"] = session.total_bytes
        report["connection_count"] = len(session.connections())
        report["captured_interfaces"] = sorted({p["interface"] for p in session.packets})
        report["metadata_directions"] = sorted({p["direction"] for p in session.packets})
        report["attributed_pids"] = sorted({p["pid"] for p in session.packets if p["pid"] is not None})
        report["attributed_effective_pids"] = sorted({p["effective_pid"] for p in session.packets
                                                     if p["effective_pid"] is not None})
        if any(p["pid"] != client.pid and p["effective_pid"] != client.pid for p in session.packets):
            raise RuntimeError("Java saved a packet without the selected PID attribution")
        if session.limit_reached or pump.stopped.get("limit_reached"):
            raise RuntimeError("Session storage limit reached")
        if pump.stopped.get("packets") != len(session.packets):
            raise RuntimeError("Java packet count differs from the saved session")
        report["scenarios"] = verify_session(session, results, client.pid, ports)
        java_inspect = _java_inspect(session_path)
        report["java_inspect"] = java_inspect
        java_hashes = {key: {"bytes": value["bytes"], "sha256": value["sha256"]}
                       for key, value in java_inspect["stream_sha256"].items()}
        report["java_streams_match_python"] = java_hashes == _stream_hashes(session)
        if not report["java_streams_match_python"]:
            raise RuntimeError("Java stream assembly differs from the Python oracle")
        if (java_inspect.get("packets") != len(session.packets)
                or java_inspect.get("connections") != len(session.connections())
                or java_inspect.get("raw_bytes") != session.total_bytes):
            raise RuntimeError("Java session inspection differs from the Python oracle")
        stats = report["capture_stats"]
        if stats.get("dropped") != 0 or stats.get("kernel_dropped") != 0:
            raise RuntimeError("Capture losses are nonzero or unavailable; zero drops were not proven")
        if len(report["scenarios"]) != 4 or not all(item["passed"] for item in report["scenarios"]):
            raise RuntimeError("At least one scenario is missing an exact captured request or response")
        report["passed"] = report["live_capture_verified"] = True
    except KeyboardInterrupt:
        failure = "Verification interrupted"
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        failure = str(error)
    finally:
        try:
            _stop_capture(capture)
        except (OSError, subprocess.SubprocessError) as error:
            failure = failure or "Java cleanup failed: " + str(error)
        if pump is not None:
            try:
                for _ in range(10):
                    if not pump.selector.get_map():
                        break
                    pump.poll(.05)
            except (OSError, ValueError, RuntimeError) as error:
                failure = failure or str(error)
            report["java_stderr_tail"] = pump.stderr_tail.decode("utf-8", "replace")
            pump.close()
        for child in (client, server):
            if child is not None:
                try:
                    network_lab.stop_child(child)
                except (OSError, subprocess.SubprocessError) as error:
                    failure = failure or "Lab cleanup failed: " + str(error)
                if child.stdin and not child.stdin.closed:
                    child.stdin.close()
        if capture is not None:
            report["java_exit_code"] = capture.returncode
            for stream in (capture.stdout, capture.stderr):
                if stream:
                    stream.close()
        if report["capture_errors"]:
            failure = failure or "Java capture reported an error"
        report["session_saved"] = session_path.exists()
        if failure:
            report["passed"] = report["live_capture_verified"] = False
        report["failure"] = failure
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for scenario in report["scenarios"]:
        directions = ", ".join(f"{name}={'OK' if value['passed'] else 'FAIL'}"
                               for name, value in scenario["directions"].items())
        print(f"{scenario['scenario']}: {directions}")
    print(f"{'PASS' if report['passed'] else 'FAIL'}: {report['packet_count']} Java-captured packets")
    if failure:
        print(failure)
    print(f"Session: {session_path}\nReport:  {report_path}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
