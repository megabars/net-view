"""Wire-format checks independent of root/BPF access or a live network."""
import io
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from netview.capture import (CaptureFormatError, CaptureService, MAX_BLOCK_SIZE,
                             MAX_QUEUE_BYTES, list_processes,
                             parse_pcapng)
from netview.models import CapturedFrame


def option(code, value, endian='<'):
    return struct.pack(endian + 'HH', code, len(value)) + value + bytes((-len(value)) % 4)


def block(kind, body, endian='<'):
    length = len(body) + 12
    assert length % 4 == 0
    return struct.pack(endian + 'II', kind, length) + body + struct.pack(endian + 'I', length)


def section(endian='<'):
    return block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)


def interface(name=b'lo0', linktype=0, endian='<', extra=b''):
    return block(1, struct.pack(endian + 'HHI', linktype, 0, 262144)
                 + option(2, name, endian) + extra, endian)


def process(pid, name, endian='<'):
    return block(0x80000001, struct.pack(endian + 'I', pid)
                 + option(2, name, endian), endian)


def packet(data=b'hello', endian='<', options=b'', original=None, ticks=1_500_000,
           interface_id=0):
    return block(6, struct.pack(endian + 'IIIII', interface_id, ticks >> 32,
                               ticks & 0xffffffff, len(data),
                               len(data) if original is None else original)
                 + data + bytes((-len(data)) % 4) + options, endian)


def attributed_capture(endian='<'):
    opts = b''.join(option(code, struct.pack(endian + 'I', value), endian)
                    for code, value in [(2, 2), (0x8001, 0), (0x8003, 1)])
    return (section(endian) + interface(endian=endian)
            + process(123, b'client', endian) + process(456, b'helper', endian)
            + packet(endian=endian, options=opts, original=100))


class PcapngTests(unittest.TestCase):
    def test_apple_process_effective_process_direction_and_original_length(self):
        for endian in ('<', '>'):
            with self.subTest(endian=endian):
                frame, = parse_pcapng(io.BytesIO(attributed_capture(endian)))
                self.assertEqual(frame, CapturedFrame(1.5, b'hello', 0, 100, 123,
                    'client', 456, 'helper', 'lo0', 'out'))

    def test_missing_metadata_stays_unknown(self):
        frame, = parse_pcapng(io.BytesIO(section() + interface() + packet()))
        self.assertIsNone(frame.pid)
        self.assertIsNone(frame.effective_pid)
        self.assertEqual(frame.direction, 'unknown')

    def test_timestamp_resolution_offset_and_inbound(self):
        for resol, ticks, expected in [(9, 1_234_567_890, 11.23456789), (0x8a, 1536, 11.5)]:
            extra = option(9, bytes([resol])) + option(14, struct.pack('<q', 10))
            data = section() + interface(extra=extra) + packet(ticks=ticks,
                options=option(2, struct.pack('<I', 1)))
            frame, = parse_pcapng(io.BytesIO(data))
            self.assertAlmostEqual(frame.timestamp, expected)
            self.assertEqual(frame.direction, 'in')

    def test_sections_reset_metadata_and_allow_new_byte_order(self):
        data = attributed_capture() + section('>') + interface(b'en0', 1, '>') + packet(endian='>')
        first, second = parse_pcapng(io.BytesIO(data))
        self.assertEqual(first.pid, 123)
        self.assertIsNone(second.pid)
        self.assertEqual((second.interface, second.linktype), ('en0', 1))

    def test_short_stream_reads_are_supported(self):
        class ShortReader(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 3))
        self.assertEqual(len(list(parse_pcapng(ShortReader(attributed_capture())))), 1)

    def test_unknown_nonpacket_block_skipped(self):
        data = section() + block(0xbad, b'abcd') + interface() + packet()
        self.assertEqual(len(list(parse_pcapng(io.BytesIO(data)))), 1)

    def test_truncated_blocks_and_invalid_lengths_fail(self):
        valid = attributed_capture()
        for tail in (1, 3, 8, 13):
            with self.subTest(truncated=tail), self.assertRaises(CaptureFormatError):
                list(parse_pcapng(io.BytesIO(valid[:-tail])))
        malformed = [b'', b'pcap data', section() + struct.pack('<II', 1, MAX_BLOCK_SIZE + 4),
                     section() + block(1, b'\x00' * 4),
                     section() + interface() + packet(original=1),
                     section() + interface() + packet(interface_id=1),
                     section() + interface() + packet(options=option(0x8001, struct.pack('<I', 0))),
                     section() + interface() + packet(options=option(2, b'x')),
                     section() + interface() + packet(options=struct.pack('<HH', 9, 100)),
                     section() + block(3, b'\0' * 4)]
        for data in malformed:
            with self.subTest(data=data[-24:]), self.assertRaises(CaptureFormatError):
                list(parse_pcapng(io.BytesIO(data)))

    def test_trailer_mismatch_fails(self):
        data = attributed_capture()
        with self.assertRaisesRegex(CaptureFormatError, 'trailer'):
            list(parse_pcapng(io.BytesIO(data[:-4] + b'\0' * 4)))

    def test_names_match_session_character_limits(self):
        for field, limit in [('process', 256), ('interface', 128)]:
            for over_limit in (False, True):
                name = ('я' * (limit + int(over_limit))).encode('utf-8')
                if field == 'process':
                    data = section() + interface() + process(123, name) + packet(
                        options=option(0x8001, struct.pack('<I', 0)))
                else:
                    data = section() + interface(name=name) + packet()
                with self.subTest(field=field, over_limit=over_limit):
                    if over_limit:
                        with self.assertRaisesRegex(CaptureFormatError, 'characters'):
                            list(parse_pcapng(io.BytesIO(data)))
                    else:
                        frame, = parse_pcapng(io.BytesIO(data))
                        self.assertEqual(len(getattr(frame, field)), limit)

    def test_zero_and_wrapped_pids_remain_unknown(self):
        for pid in (0, 0xffffffff):
            data = section() + interface() + process(pid, b'unknown') + packet(
                options=option(0x8001, struct.pack('<I', 0)))
            with self.subTest(pid=pid):
                frame, = parse_pcapng(io.BytesIO(data))
                self.assertIsNone(frame.pid)

    def test_process_and_metadata_limits(self):
        with patch('netview.capture.MAX_TABLE_ENTRIES', 1), self.assertRaisesRegex(
                CaptureFormatError, 'process table'):
            list(parse_pcapng(io.BytesIO(attributed_capture())))
        with patch('netview.capture.MAX_METADATA_BYTES', 2), self.assertRaisesRegex(
                CaptureFormatError, 'memory limit'):
            list(parse_pcapng(io.BytesIO(section() + interface())))

    @unittest.skipUnless(sys.platform == 'darwin', 'Apple tcpdump is macOS only')
    def test_fixture_metadata_accepted_by_actual_apple_tcpdump(self):
        # Deliberately a non-IP payload: this check is about Apple's metadata ABI.
        with tempfile.NamedTemporaryFile(suffix='.pcapng') as capture:
            capture.write(attributed_capture())
            capture.flush()
            result = subprocess.run(['/usr/sbin/tcpdump', '-nr', capture.name, '-k', 'INPD'],
                                    capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('lo0', result.stdout)
        self.assertIn('client', result.stdout)
        self.assertIn('123', result.stdout)


    @unittest.skipUnless(sys.platform == 'darwin', 'Apple tcpdump is macOS only')
    def test_native_tcpdump_rewrites_pcapng_and_filters_pid_and_effective_pid(self):
        with tempfile.NamedTemporaryFile(suffix='.pcapng') as capture:
            capture.write(attributed_capture())
            capture.flush()
            for expression, expected_count in [('pid=123', 1), ('epid=456', 1), ('pid=999', 0)]:
                with self.subTest(expression=expression):
                    result = subprocess.run(['/usr/sbin/tcpdump', '-nr', capture.name,
                        '-P', '-w', '-', '-Q', expression], capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    rewritten = list(parse_pcapng(io.BytesIO(result.stdout)))
                    self.assertEqual(len(rewritten), expected_count)
                    if rewritten:
                        self.assertEqual(rewritten, list(parse_pcapng(io.BytesIO(attributed_capture()))))


class CaptureServiceTests(unittest.TestCase):
    def wait_done(self, service):
        deadline = time.monotonic() + 5
        while service.running and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertFalse(service.running, 'Capture worker failed to stop')
        events = []
        while not service.events.empty():
            events.append(service.events.get_nowait())
        return events

    def test_process_listing_only_requests_pid_and_comm(self):
        result = subprocess.CompletedProcess([], 0,
            '  42 /Applications/Some App.app/Contents/MacOS/Some App\n 1 launchd\nbad\n', '')
        with patch('netview.capture.subprocess.run', return_value=result) as run:
            processes = list_processes()
        self.assertEqual(run.call_args.args[0], ['/bin/ps', '-axo', 'pid=,comm='])
        self.assertEqual(processes[1], {'pid': 42, 'name': 'Some App',
            'path': '/Applications/Some App.app/Contents/MacOS/Some App'})

    def test_offline_module_import_does_not_require_posix_pwd(self):
        result = subprocess.run([sys.executable, '-c',
            'import sys; sys.modules["pwd"] = None; import netview.capture'],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_windows_process_listing_reports_unsupported_without_spawning(self):
        with patch('netview.capture.sys.platform', 'win32'), patch(
                'netview.capture.subprocess.run') as run:
            with self.assertRaisesRegex(RuntimeError, 'unavailable on Windows'):
                list_processes()
        run.assert_not_called()

    def test_invalid_selection_rejected(self):
        service = CaptureService()
        for pids in (set(), {-1}, {True}, {'123'}, {2**32}):
            with self.subTest(pids=pids), self.assertRaises(ValueError):
                service.start(pids)
        self.assertFalse(service.running)

    def test_failure_emits_error_and_stopped_without_blocking(self):
        service = CaptureService()
        with patch('netview.capture.sys.platform', 'darwin'), patch(
                'netview.capture.subprocess.Popen', side_effect=OSError('capture unavailable')):
            service.start({123})
            events = self.wait_done(service)
        self.assertEqual([event['type'] for event in events], ['error', 'stats', 'stopped'])
        self.assertIn('capture unavailable', events[0]['message'])

    def test_queue_byte_bound_drop_count_and_reserved_control_slots(self):
        service = CaptureService()
        frame = CapturedFrame(0, bytes(1024 * 1024), 1)
        for _ in range(100):
            service._emit({'type': 'packet', 'frame': frame})
        self.assertEqual(service.events.packet_bytes, MAX_QUEUE_BYTES)
        self.assertEqual(service._dropped, 68)
        service._stats()
        service._emit({'type': 'stopped'})
        self.assertEqual(service.events.qsize(), 34)
        for _ in range(32):
            service.events.get_nowait()
        self.assertEqual(service.events.packet_bytes, 0)
        self.assertEqual(service.events.get_nowait()['dropped'], 68)
        self.assertEqual(service.events.get_nowait()['type'], 'stopped')

    def test_worker_filters_actual_metadata_and_reports_stream_end(self):
        service = CaptureService()
        # Real pipes exercise incremental reading and stderr drainage without BPF.
        child_code = ('import sys; sys.stderr.write("tcpdump: listening on pktap,all\\n"); '
                      'sys.stderr.flush(); sys.stdout.buffer.write(' + repr(attributed_capture()) + '); '
                      'sys.stdout.flush()')
        real_popen = subprocess.Popen
        commands = []
        def spawn(command, **kwargs):
            commands.append((command, kwargs))
            return real_popen([sys.executable, '-c', child_code], **kwargs)
        with patch('netview.capture.sys.platform', 'darwin'), patch(
                'netview.capture.subprocess.Popen', side_effect=spawn):
            service.start({456})
            events = self.wait_done(service)
        self.assertEqual(sum(event['type'] == 'ready' for event in events), 1)
        frames = [event['frame'] for event in events if event['type'] == 'packet']
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].effective_pid, 456)
        self.assertEqual(events[-1]['type'], 'stopped')
        command, kwargs = commands[0]
        self.assertEqual(command[:3], ['/usr/bin/sudo', '-n', '/usr/sbin/tcpdump'])
        self.assertEqual(command[command.index('-Q') + 1], '(pid=456 or epid=456)')
        self.assertIn('-Z', command)
        self.assertIn('-P', command)
        self.assertEqual(kwargs['process_group'], 0)
        self.assertNotIn('start_new_session', kwargs)

    def test_stop_interrupts_idle_pipe_and_reaps_child(self):
        service = CaptureService()
        real_popen = subprocess.Popen
        children = []
        def spawn(command, **kwargs):
            child = real_popen([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
            children.append(child)
            return child
        with patch('netview.capture.sys.platform', 'darwin'), patch(
                'netview.capture.subprocess.Popen', side_effect=spawn):
            service.start({123})
            deadline = time.monotonic() + 2
            while not children and time.monotonic() < deadline:
                time.sleep(.01)
            service.stop()
            events = self.wait_done(service)
        self.assertTrue(children)
        self.assertIsNotNone(children[0].poll())
        self.assertFalse(any(event['type'] == 'error' for event in events))
        self.assertEqual(events[-1]['type'], 'stopped')


if __name__ == '__main__':
    unittest.main()
