# macOS capture adapter

The GUI runs as the normal user. `CaptureService` starts the system executable as:

```text
/usr/bin/sudo -n /usr/sbin/tcpdump -i pktap,all -s 0 -U -P -w - \
    -Q '(pid=N or epid=N)' -Z CURRENT_USER 'ip or ip6'
```

For several selected PIDs, the metadata expression ORs every PID and effective PID.
Arguments are passed directly, without a shell. PID values are validated integers.
`-P` explicitly selects Apple's pcapng output; `-Z` drops tcpdump's privileges after
opening capture devices. The GUI never requests, receives, or stores a password
and never changes BPF permissions. User authentication, when needed, takes place
in Terminal with `sudo -v` before launching the app from that same Terminal.
The child gets a separate process group within the same session, preserving the
controlling terminal used by sudo's credential cache. A fresh session would lose
that association. This implementation requires Python 3.11+ (`process_group=0`).

`stop()` sets cancellation and signals the child process group. The worker closes
the output pipe and reaps the child, with bounded escalation to SIGKILL. `-Z`
keeps tcpdump signalable by the GUI user; the closed pipe also makes further output
fail with EPIPE. stderr is drained by a separate bounded reader. Shutdown does not
wait on incoming network traffic. The caller must call `stop()` when closing its
window. Live capture on other platforms reports an explicit error.

## Public API

- `list_processes() -> list[dict]`: sorted PID/name/path records from
  `/bin/ps -axo pid=,comm=`. It never requests process command-line arguments.
  Windows reports an explicit unsupported error; offline parsing/session access
  remains importable without POSIX-only modules.
- `parse_pcapng(stream: BinaryIO) -> Iterator[CapturedFrame]`: incremental offline
  reader; malformed or unsupported input raises `CaptureFormatError` (`ValueError`).
- `CaptureService()`: `events` is a `queue.Queue` with `maxsize=2000`.
- `start(pids: set[int], interface='pktap,all') -> None`: starts a background worker.
  Invalid selections raise `ValueError`; starting while active raises `RuntimeError`.
- `stop() -> None`: requests cancellation without waiting on the worker.
- `running: bool`: true while the worker remains alive, including shutdown.

Events are dictionaries:

```python
{'type': 'ready'}
{'type': 'packet', 'frame': CapturedFrame(...)}
{'type': 'error', 'message': '...'}
{'type': 'stats', 'dropped': 0, 'kernel_dropped': None}
{'type': 'stopped'}
```

`ready` means tcpdump reported that its device is listening or a valid section
header arrived. It does not promise packets have arrived. Every termination emits
`stopped`; unexpected EOF, subprocess errors, and parse failures emit `error` first.
Errors include the bounded stderr tail and Terminal authentication guidance for
sudo failures. Packet delivery is checked again against actual PID/effective PID
metadata, even after applying tcpdump's metadata filter. No ownership is inferred
from ports, addresses, or the selected process.

The queue reserves 16 slots for control events and limits queued packet bytes to
32 MiB. Excess packets increment the cumulative adapter `dropped` counter, reported
periodically while packets arrive and at shutdown. In an unattended full queue,
control events can replace an old event to keep errors and termination observable.
`kernel_dropped` is a separate count, unknown until tcpdump reports it on stderr;
zero is never substituted for an unavailable count.

## On-disk metadata

Wire values are based on Apple's primary source
[pcap/pcap-ng.h](https://github.com/apple-oss-distributions/libpcap/blob/main/libpcap/pcap/pcap-ng.h)
and the installed `tcpdump(1)` manual (Apple version 161).

| Structure | Fields used |
| --- | --- |
| Section Header Block (`0x0a0d0d0a`) | Byte order, major version 1; resets section tables |
| Interface Description Block (`1`) | Linktype; option 2 name, option 9 timestamp resolution, option 14 timestamp offset |
| Apple Process Information Block (`0x80000001`) | PID; option 2 process name |
| Enhanced Packet Block (`6`) | Interface ID, timestamp, captured/original lengths, packet bytes |
| EPB option `0x8001` | Zero-based process block index within current section |
| EPB option `0x8003` | Effective process block index within current section |
| EPB option `2` | Low two bits: 1 inbound (`in`), 2 outbound (`out`), otherwise `unknown` |

Both byte orders, decimal/binary timestamp resolutions, and multiple sections are
supported. Packets retain their interface's linktype and native packet bytes for
the protocol layer. Missing PID/effective PID, zero, and wrapped unsigned sentinel PIDs remain
`None`; absent names remain empty. Unknown non-packet blocks/options are skipped. Classic pcap, obsolete Packet
Blocks and Simple Packet Blocks are explicitly rejected. Raw PKTAP decoding is not
implemented: native tcpdump writes IDB/PIB/EPB metadata with the forced pcapng mode.

Block lengths/trailers, packet bounds, options, numeric option widths, and table
references are checked. A block is limited to 4 MiB, each section table to 16,384
entries, retained metadata strings to 8 MiB total, and each encoded name to 4,096 bytes. Process names additionally have a
256-character limit and interface names a 128-character limit, matching session
validation.
Exceeding a limit stops capture with an explicit error.

## Verification and limits

`python3 -m unittest discover -s tests -p test_capture.py -v` covers both endian
orders, PID/effective PID, direction, timestamps, section resets, absent metadata,
short reads, malformed/truncated blocks, resource limits, bounded queue losses,
process listing privacy, error delivery, and stopping/reaping an idle subprocess.

On this machine, Apple's real `tcpdump -r` accepts the generated metadata fixture.
Offline `tcpdump -P -w -` roundtrips it unchanged through this parser; `pid=123` and
`epid=456` both select it, while an unrelated PID selects no packets. These are
native executable/offline tests, not proof of live BPF capture by themselves.

Live capture was subsequently verified by the user running
`python3 tools/check_live_capture.py` in their authenticated Terminal. Run
`20261028-201526-2bad5b1b` captured 60 actual loopback IPv4 packets attributed to
client PID 33314, recovered both directions of all four lab scenarios by exact
SHA-256, and reported zero adapter/kernel drops. The saved session was reloaded
and verified again. See `docs/MVP_CHECKS.md` and the report under `results/`.
Effective-PID and IPv6 live capture are not covered by that run. System device
permissions were not changed; no password was obtained by the app or agent.

Only IP traffic is requested. PID attribution has the visibility and limitations
of Apple's metadata, including helper processes and unavailable attribution.
Loopback or several interfaces can produce duplicate observations. TLS plaintext,
missing packets, and missing process metadata are never reconstructed by this
adapter. IP fragmentation and transport parsing belong to the separate protocol
layer.
