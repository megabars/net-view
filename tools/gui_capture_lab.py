#!/usr/bin/env python3
"""Keep one lab client PID alive for manual GUI start/stop/restart checks.

Type a label to run all four localhost scenarios; type quit to stop the server.
Each run writes independent client hashes under results/. No packet capture here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import network_lab


def main() -> None:
    server, ports = network_lab.start_child(SimpleNamespace(http_port=0, tcp_port=0, udp_port=0))
    directory = ROOT / "results"
    directory.mkdir(exist_ok=True)
    run_id = uuid.uuid4().hex[:8]
    print(json.dumps({"ready": True, "client_pid": os.getpid(), "ports": ports,
                      "run_id": run_id}), flush=True)
    try:
        for line in sys.stdin:
            label = line.strip()
            if label == "quit":
                break
            if not re.fullmatch(r"[a-z0-9-]{1,40}", label):
                print("Use a short lowercase label or quit", flush=True)
                continue
            path = directory / f"java-gui-{run_id}-{label}.client.json"
            if path.exists():
                print("Label already used; choose a new one", flush=True)
                continue
            results = [network_lab.exchange(s, ports) for s in network_lab.SCENARIOS]
            record = {"client_pid": os.getpid(), "ports": ports, "results": results}
            path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"completed": label, "matched": all(r["matched"] for r in results),
                              "record": str(path)}), flush=True)
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


if __name__ == "__main__":
    main()
