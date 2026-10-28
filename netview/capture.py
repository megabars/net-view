"""macOS tcpdump capture and a bounded reader for Apple's pcapng metadata.

Wire constants follow Apple's libpcap/pcap/pcap-ng.h; see docs/CAPTURE.md.
No socket/port heuristics are used to assign process ownership.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import queue
import re
import select
import signal
import struct
import subprocess
import sys
import threading
import time
from typing import BinaryIO, Callable, Iterator

from .models import CapturedFrame

MAX_BLOCK_SIZE = 4 * 1024 * 1024
MAX_TABLE_ENTRIES = 16384
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_QUEUE_BYTES = 32 * 1024 * 1024


class CaptureFormatError(ValueError):
    """Malformed, unsupported, or resource-exhausting capture input."""


def _read_exact(stream: BinaryIO, size: int, *, eof_ok: bool = False) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            if not data and eof_ok:
                return b""
            raise CaptureFormatError("Truncated pcapng block")
        data.extend(chunk)
    return bytes(data)


def _options(data: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise CaptureFormatError("Truncated pcapng option header")
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        padded = (length + 3) & ~3
        if offset + padded > len(data):
            raise CaptureFormatError("Pcapng option extends beyond its block")
        if code == 0:
            if length != 0:
                raise CaptureFormatError("Invalid end-of-options length")
            return
        yield code, data[offset:offset + length]
        offset += padded


def _number(value: bytes, endian: str, fmt: str = "I") -> int:
    if len(value) != struct.calcsize(fmt):
        raise CaptureFormatError("Invalid numeric pcapng option length")
    return struct.unpack(endian + fmt, value)[0]


def _text(value: bytes, maximum: int) -> str:
    if len(value) > 4096:
        raise CaptureFormatError("Pcapng metadata string exceeds 4096 bytes")
    text = value.rstrip(b"\0").decode("utf-8", "replace")
    if len(text) > maximum:
        raise CaptureFormatError(f"Pcapng metadata name exceeds {maximum} characters")
    return text


@dataclass
class _Interface:
    linktype: int
    name: str = ""
    resolution: float = 1e-6
    offset: int = 0


def parse_pcapng(stream: BinaryIO) -> Iterator[CapturedFrame]:
    """Yield EPB frames, preserving Apple PID/effective PID and IDB metadata.

    Supports either byte order, multiple sections, decimal/binary timestamp
    resolution, and timestamp offsets. Unknown non-packet blocks are skipped.
    Invalid/truncated input raises CaptureFormatError. Packet Blocks and Simple
    Packet Blocks are rejected because this adapter requires EPB timestamps.
    Reads incrementally without retaining packet data after the caller releases it.
    """
    yield from _parse_pcapng(stream)


def _parse_pcapng(stream: BinaryIO, on_ready: Callable[[], None] | None = None
                  ) -> Iterator[CapturedFrame]:
    endian: str | None = None
    interfaces: list[_Interface] = []
    processes: list[tuple[int | None, str]] = []
    metadata_bytes = 0
    while True:
        header = _read_exact(stream, 8, eof_ok=True)
        if not header:
            if endian is None:
                raise CaptureFormatError("No pcapng section header received")
            return
        is_section = header[:4] == b"\x0a\x0d\x0d\x0a"
        if is_section:
            magic = _read_exact(stream, 4)
            if magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureFormatError("Invalid pcapng byte-order magic")
        elif endian is None:
            raise CaptureFormatError("Expected pcapng section header; classic pcap is unsupported")
        block_type, length = struct.unpack(endian + "II", header)
        minimum = 28 if is_section else 12
        if length < minimum or length % 4 or length > MAX_BLOCK_SIZE:
            raise CaptureFormatError(f"Invalid or oversized pcapng block length: {length}")
        rest = _read_exact(stream, length - (12 if is_section else 8))
        if struct.unpack_from(endian + "I", rest, len(rest) - 4)[0] != length:
            raise CaptureFormatError("Pcapng block length trailer does not match header")
        body = (magic if is_section else b"") + rest[:-4]
        if is_section:
            major, _minor = struct.unpack_from(endian + "HH", body, 4)
            if major != 1:
                raise CaptureFormatError(f"Unsupported pcapng major version: {major}")
            # Validate options before reporting successful initialization.
            list(_options(body[16:], endian))
            interfaces.clear()
            processes.clear()
            metadata_bytes = 0
            if on_ready:
                on_ready()
        elif block_type == 1:
            if len(body) < 8:
                raise CaptureFormatError("Truncated interface description")
            if len(interfaces) >= MAX_TABLE_ENTRIES:
                raise CaptureFormatError("Pcapng interface table limit reached")
            linktype, _reserved, _snaplen = struct.unpack_from(endian + "HHI", body)
            interface = _Interface(linktype)
            for code, value in _options(body[8:], endian):
                if code == 2:
                    interface.name = _text(value, 128)
                    metadata_bytes += len(value)
                elif code == 9:
                    resolution = _number(value, endian, "B")
                    interface.resolution = (2.0 ** -(resolution & 127) if resolution & 128
                                            else 10.0 ** -resolution)
                elif code == 14:
                    interface.offset = _number(value, endian, "q")
            interfaces.append(interface)
        elif block_type == 0x80000001:
            if len(body) < 4:
                raise CaptureFormatError("Truncated Apple process information block")
            if len(processes) >= MAX_TABLE_ENTRIES:
                raise CaptureFormatError("Pcapng process table limit reached")
            raw_pid = struct.unpack_from(endian + "I", body)[0]
            pid = raw_pid if 0 < raw_pid <= 0x7fffffff else None
            name = ""
            for code, value in _options(body[4:], endian):
                if code == 2:
                    name = _text(value, 256)
                    metadata_bytes += len(value)
            processes.append((pid, name))
        elif block_type == 6:
            if len(body) < 20:
                raise CaptureFormatError("Truncated enhanced packet block")
            interface_id, hi, lo, caplen, original = struct.unpack_from(endian + "IIIII", body)
            padded = (caplen + 3) & ~3
            if caplen > original or 20 + padded > len(body):
                raise CaptureFormatError("Invalid captured packet length")
            if interface_id >= len(interfaces):
                raise CaptureFormatError("Packet references an unknown interface")
            interface = interfaces[interface_id]
            pid = effective_pid = None
            name = effective_name = ""
            direction = "unknown"
            for code, value in _options(body[20 + padded:], endian):
                if code == 2:
                    flags = _number(value, endian) & 3
                    direction = {1: "in", 2: "out"}.get(flags, "unknown")
                elif code in (0x8001, 0x8003):
                    index = _number(value, endian)
                    if index >= len(processes):
                        raise CaptureFormatError("Packet references an unknown Apple process block")
                    if code == 0x8001:
                        pid, name = processes[index]
                    else:
                        effective_pid, effective_name = processes[index]
            yield CapturedFrame(
                timestamp=((hi << 32) | lo) * interface.resolution + interface.offset,
                data=body[20:20 + caplen], linktype=interface.linktype,
                original_length=original, pid=pid, process=name,
                effective_pid=effective_pid, effective_process=effective_name,
                interface=interface.name, direction=direction,
            )
        elif block_type in (2, 3):
            raise CaptureFormatError("Only Enhanced Packet Blocks are supported")
        if metadata_bytes > MAX_METADATA_BYTES:
            raise CaptureFormatError("Pcapng metadata memory limit reached")


def list_processes() -> list[dict]:
    """List PID and executable names/paths, never command-line arguments."""
    if sys.platform == "win32":
        raise RuntimeError("Process listing is unavailable on Windows; saved sessions can still be opened")
    result = subprocess.run(["/bin/ps", "-axo", "pid=,comm="], capture_output=True,
                            text=True, check=True, timeout=5)
    processes = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        path = parts[1]
        processes.append({"pid": int(parts[0]), "name": Path(path).name, "path": path})
    return sorted(processes, key=lambda item: (item["name"].casefold(), item["pid"]))


class _EventQueue(queue.Queue):
    """Queue with a separate byte budget for packets and reserved control slots."""
    def __init__(self):
        super().__init__(maxsize=2000)
        self.packet_bytes = 0

    def _put(self, item):
        if item["type"] == "packet":
            size = len(item["frame"].data)
            if self._qsize() >= self.maxsize - 16 or self.packet_bytes + size > MAX_QUEUE_BYTES:
                raise queue.Full
            self.packet_bytes += size
        super()._put(item)

    def _get(self):
        item = super()._get()
        if item["type"] == "packet":
            self.packet_bytes -= len(item["frame"].data)
        return item


class _CancelablePipe:
    def __init__(self, pipe, stop_event):
        self.pipe = pipe
        self.stop_event = stop_event

    def read(self, size):
        while not self.stop_event.is_set():
            readable, _, _ = select.select([self.pipe], [], [], 0.2)
            if readable:
                return os.read(self.pipe.fileno(), size)
        return b""


class CaptureService:
    """Single capture worker. start()/stop() never wait for network or passwords.

    Events: ready; packet(frame); error(message); stats(dropped, kernel_dropped);
    stopped. ``dropped`` counts frames lost from this adapter's bounded queue.
    ``kernel_dropped`` is None until tcpdump reports a kernel-drop count.
    """
    def __init__(self):
        self.events = _EventQueue()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._process: subprocess.Popen | None = None
        self._dropped = 0
        self._kernel_dropped: int | None = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, pids: set[int], interface: str = "pktap,all") -> None:
        if self.running:
            raise RuntimeError("Capture is already running")
        if not pids or len(pids) > 256 or any(type(pid) is not int or not 0 < pid <= 0x7fffffff
                                             for pid in pids):
            raise ValueError("Select 1–256 positive numeric process IDs")
        if interface != "pktap,all":
            raise ValueError("This adapter supports only macOS pktap,all")
        # Previous events belong to a previous run and must not cross sessions.
        while True:
            try:
                self.events.get_nowait()
            except queue.Empty:
                break
        self._stop.clear()
        self._ready.clear()
        self._dropped = 0
        self._kernel_dropped = None
        self._thread = threading.Thread(target=self._run, args=(set(pids), interface),
                                        name="netview-capture", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._signal(signal.SIGTERM)

    def _signal(self, signum):
        with self._lock:
            process = self._process
            if process is not None and process.poll() is None:
                try:
                    # tcpdump drops to our UID with -Z, so it remains signalable
                    # even when sudo uses a privileged monitor process.
                    os.killpg(process.pid, signum)
                except (ProcessLookupError, PermissionError):
                    try:
                        process.send_signal(signum)
                    except (ProcessLookupError, PermissionError):
                        pass

    def _emit(self, event):
        try:
            self.events.put_nowait(event)
        except queue.Full:
            if event["type"] == "packet":
                self._dropped += 1
                return
            # Never block capture teardown or errors behind an unattended GUI.
            try:
                removed = self.events.get_nowait()
                if removed["type"] == "packet":
                    self._dropped += 1
            except queue.Empty:
                pass
            try:
                self.events.put_nowait(event)
            except queue.Full:
                pass

    def _mark_ready(self):
        with self._lock:
            if not self._ready.is_set() and not self._stop.is_set():
                self._ready.set()
                self._emit({"type": "ready"})

    def _stats(self):
        self._emit({"type": "stats", "dropped": self._dropped,
                    "kernel_dropped": self._kernel_dropped})

    def _drain_stderr(self, pipe, tail):
        # readline(size) bounds even an unterminated stderr line.
        while True:
            raw = pipe.readline(4096)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").strip()
            tail.append(line)
            if "listening on " in line:
                self._mark_ready()
            match = re.search(r"(\d+) packets? dropped by kernel", line)
            if match:
                self._kernel_dropped = int(match.group(1))

    def _run(self, pids, interface):
        process = None
        stderr_thread = None
        tail = deque(maxlen=16)
        failure = None
        try:
            if sys.platform != "darwin":
                raise RuntimeError("Live capture requires macOS with Apple's tcpdump")
            import pwd  # Darwin-only; offline parsing remains importable on Windows.
            user = pwd.getpwuid(os.getuid()).pw_name
            metadata_filter = "(" + " or ".join(
                f"pid={pid} or epid={pid}" for pid in sorted(pids)) + ")"
            command = ["/usr/bin/sudo", "-n", "/usr/sbin/tcpdump", "-i", interface,
                       "-s", "0", "-U", "-P", "-w", "-", "-Q", metadata_filter,
                       "-Z", user, "ip or ip6"]
            if self._stop.is_set():
                return
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       bufsize=0, process_group=0)
            with self._lock:
                self._process = process
            if self._stop.is_set():
                self._signal(signal.SIGTERM)
            stderr_thread = threading.Thread(target=self._drain_stderr,
                                             args=(process.stderr, tail), daemon=True,
                                             name="netview-capture-stderr")
            stderr_thread.start()
            last_stats = time.monotonic()
            stream = _CancelablePipe(process.stdout, self._stop)
            for frame in _parse_pcapng(stream, self._mark_ready):
                if self._stop.is_set():
                    break
                # Defense in depth: metadata filter behavior can vary by OS.
                if frame.pid in pids or frame.effective_pid in pids:
                    self._emit({"type": "packet", "frame": frame})
                if time.monotonic() - last_stats >= 1:
                    self._stats()
                    last_stats = time.monotonic()
            if not self._stop.is_set():
                failure = "Capture stream ended unexpectedly"
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            if not self._stop.is_set():
                failure = str(exc)
        finally:
            if process is not None:
                self._signal(signal.SIGTERM)
                # Closing our only read end also gives tcpdump EPIPE on output.
                process.stdout.close()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._signal(signal.SIGKILL)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        failure = "Capture subprocess did not stop; check Terminal"
                if stderr_thread is not None:
                    stderr_thread.join(timeout=0.5)
                process.stderr.close()
                with self._lock:
                    self._process = None
            if failure:
                diagnostic = "\n".join(tail)
                message = failure + ("\n" + diagnostic if diagnostic else "")
                if "password" in diagnostic.lower() or "sudo:" in diagnostic.lower():
                    message += ("\nAuthenticate in Terminal with sudo -v, then launch the "
                                "app from that same Terminal. The app never requests a password.")
                self._emit({"type": "error", "message": message})
            self._stats()
            self._emit({"type": "stopped"})
