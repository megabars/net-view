package netview.capture;

import netview.model.CapturedFrame;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import java.util.Arrays;

import static netview.capture.PcapngFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class PcapngReaderTest {
    private static final ByteOrder LE = ByteOrder.LITTLE_ENDIAN, BE = ByteOrder.BIG_ENDIAN;
    private CapturedFrame read(byte[] data) throws IOException {
        try (var reader = new PcapngReader(new ByteArrayInputStream(data))) { return reader.next(); }
    }
    @Test void appleMetadataBothByteOrders() throws Exception {
        for (ByteOrder order : new ByteOrder[]{LE, BE}) {
            try (var reader = new PcapngReader(new ByteArrayInputStream(attributed(order)))) {
                assertEquals(new CapturedFrame(1.5, "hello".getBytes(StandardCharsets.UTF_8), 0, 100,
                        123L, "client", 456L, "helper", "lo0", "out"), reader.next());
                assertNull(reader.next());
                assertNull(reader.next());
            }
        }
    }
    @Test void missingMetadataStaysUnknown() throws Exception {
        CapturedFrame frame = read(join(section(LE), iface(LE, "lo0", 0), packet(LE)));
        assertNull(frame.pid()); assertNull(frame.effectivePid()); assertEquals("unknown", frame.direction());
    }
    @Test void resolutionOffsetAndDirection() throws Exception {
        for (int resolution : new int[]{9, 0x8a}) {
            long ticks = resolution == 9 ? 1_234_567_890L : 1536;
            byte[] offset = ByteBuffer.allocate(8).order(LE).putLong(10).array();
            byte[] data = join(section(LE), iface(LE, "lo0", 0, option(LE, 9, new byte[]{(byte) resolution}),
                    option(LE, 14, offset)), packet(LE, new byte[]{1}, 1, ticks, 0, option(LE, 2, numbers(LE, 1))));
            CapturedFrame frame = read(data);
            assertEquals(resolution == 9 ? 11.23456789 : 11.5, frame.timestamp(), 1e-8);
            assertEquals("in", frame.direction());
        }
    }
    @Test void newSectionsResetTablesAndByteOrder() throws Exception {
        try (var reader = new PcapngReader(new ByteArrayInputStream(join(attributed(LE), section(BE),
                iface(BE, "en0", 1), packet(BE))))) {
            assertEquals(123L, reader.next().pid());
            CapturedFrame frame = reader.next();
            assertNull(frame.pid()); assertEquals("en0", frame.networkInterface()); assertEquals(1, frame.linktype());
        }
    }
    @Test void shortAndZeroLengthReadsSupported() throws Exception {
        var stream = new ByteArrayInputStream(attributed(LE)) {
            private boolean zero;
            @Override public synchronized int read(byte[] target, int offset, int length) {
                zero = !zero;
                return zero ? 0 : super.read(target, offset, Math.min(3, length));
            }
        };
        try (var reader = new PcapngReader(stream)) { assertNotNull(reader.next()); assertNull(reader.next()); }
    }
    @Test void unknownNonpacketBlocksSkipped() throws Exception {
        assertNotNull(read(join(section(LE), block(LE, 0xbad, numbers(LE, 5)), iface(LE, "", 0), packet(LE))));
    }
    @Test void malformedAndTruncatedInputRejected() {
        byte[] valid = attributed(LE);
        for (int tail : new int[]{1, 3, 8, 13})
            assertThrows(IOException.class, () -> read(Arrays.copyOf(valid, valid.length - tail)));
        byte[][] invalid = {
                new byte[0], "pcap data".getBytes(StandardCharsets.US_ASCII),
                join(section(LE), numbers(LE, 1, PcapngReader.MAX_BLOCK_SIZE + 4)),
                join(section(LE), block(LE, 1, new byte[4])),
                join(section(LE), iface(LE, "", 0), packet(LE, new byte[]{1, 2}, 1, 0, 0)),
                join(section(LE), iface(LE, "", 0), packet(LE, new byte[0], 0, 0, 1)),
                join(section(LE), iface(LE, "", 0), packet(LE, option(LE, 0x8001, numbers(LE, 0)))),
                join(section(LE), iface(LE, "", 0), packet(LE, option(LE, 2, new byte[]{1}))),
                join(section(LE), iface(LE, "", 0), packet(LE, new byte[]{9, 0, 100, 0})),
                join(section(LE), block(LE, 3, numbers(LE, 0))),
                join(section(LE), iface(LE, "", 0), packet(LE, option(LE, 0, new byte[]{1})))
        };
        for (byte[] input : invalid) assertThrows(IOException.class, () -> read(input));
    }
    @Test void mismatchingTrailerRejected() {
        byte[] data = attributed(LE); Arrays.fill(data, data.length - 4, data.length, (byte) 0);
        assertTrue(assertThrows(IOException.class, () -> read(data)).getMessage().contains("trailer"));
    }
    @Test void utf8CharacterLimitsMatchModel() throws Exception {
        for (String character : new String[]{"я", "😀"}) {
            for (int limit : new int[]{128, 256}) {
                String name = character.repeat(limit);
                byte[] accepted = limit == 128 ? join(section(LE), iface(LE, name, 0), packet(LE))
                        : join(section(LE), iface(LE, "", 0), process(LE, 123, name), packet(LE, option(LE, 0x8001, numbers(LE, 0))));
                assertNotNull(read(accepted));
                String tooLong = name + character;
                byte[] rejected = limit == 128 ? join(section(LE), iface(LE, tooLong, 0), packet(LE))
                        : join(section(LE), process(LE, 123, tooLong));
                assertTrue(assertThrows(IOException.class, () -> read(rejected)).getMessage().contains("characters"));
            }
        }
    }
    @Test void sentinelPidsStayUnknown() throws Exception {
        for (long pid : new long[]{0, 0xffff_ffffL, 0x8000_0000L}) {
            CapturedFrame frame = read(join(section(LE), iface(LE, "", 0), process(LE, pid, "unknown"),
                    packet(LE, option(LE, 0x8001, numbers(LE, 0)))));
            assertNull(frame.pid());
        }
    }
    @Test void nativeAppleTcpdumpReadsAndFiltersProcessMetadata() throws Exception {
        Assumptions.assumeTrue(System.getProperty("os.name", "").toLowerCase().contains("mac")
                && Files.isExecutable(Path.of("/usr/sbin/tcpdump")));
        Path capture = Files.createTempFile("netview-java-wire-", ".pcapng");
        try {
            Files.write(capture, attributed(LE));
            for (String filter : new String[]{"pid=123", "epid=456", "pid=999"}) {
                Process child = new ProcessBuilder("/usr/sbin/tcpdump", "-nr", capture.toString(),
                        "-P", "-w", "-", "-Q", filter).start();
                if (!child.waitFor(5, TimeUnit.SECONDS)) { child.destroyForcibly(); fail("Native offline tcpdump timed out"); }
                assertEquals(0, child.exitValue(), new String(child.getErrorStream().readAllBytes(), StandardCharsets.UTF_8));
                try (var reader = new PcapngReader(new ByteArrayInputStream(child.getInputStream().readAllBytes()))) {
                    if (filter.equals("pid=999")) assertNull(reader.next());
                    else { assertEquals(read(attributed(LE)), reader.next()); assertNull(reader.next()); }
                }
            }
        } finally { Files.deleteIfExists(capture); }
    }

    @Test void resourceLimitsEnforced() {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); out.writeBytes(section(LE));
        for (int i = 0; i <= PcapngReader.MAX_TABLE_ENTRIES; i++) out.writeBytes(process(LE, 123, ""));
        assertTrue(assertThrows(IOException.class, () -> read(out.toByteArray())).getMessage().contains("process table"));
        out.reset(); out.writeBytes(section(LE));
        byte[] encodedName = new byte[4096]; encodedName[0] = 'a';
        for (int i = 0; i <= PcapngReader.MAX_METADATA_BYTES / 4096; i++)
            out.writeBytes(iface(LE, encodedName, 0));
        assertTrue(assertThrows(IOException.class, () -> read(out.toByteArray())).getMessage().contains("memory limit"));
    }
}
