package netview.capture;

import netview.model.CapturedFrame;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Incremental, bounded pcapng reader, including Apple's process information blocks. */
public final class PcapngReader implements AutoCloseable {
    public static final int MAX_BLOCK_SIZE = 4 * 1024 * 1024;
    public static final int MAX_TABLE_ENTRIES = 16_384;
    public static final int MAX_METADATA_BYTES = 8 * 1024 * 1024;
    private final InputStream stream;
    private final Runnable onReady;
    private final List<InterfaceInfo> interfaces = new ArrayList<>();
    private final List<ProcessMetadata> processes = new ArrayList<>();
    private ByteOrder order;
    private long metadataBytes;
    private boolean ended;

    private record InterfaceInfo(int linktype, String name, double resolution, long offset) {}
    private record ProcessMetadata(Long pid, String name) {}
    @FunctionalInterface private interface OptionVisitor { void accept(int code, ByteBuffer value) throws IOException; }

    public PcapngReader(InputStream stream) { this(stream, () -> {}); }
    PcapngReader(InputStream stream, Runnable onReady) {
        this.stream = Objects.requireNonNull(stream);
        this.onReady = Objects.requireNonNull(onReady);
    }

    public CapturedFrame next() throws IOException {
        if (ended) return null;
        while (true) {
            byte[] header = readExact(8, true);
            if (header == null) {
                if (order == null) throw invalid("No pcapng section header received");
                ended = true;
                return null;
            }
            boolean section = header[0] == 0x0a && header[1] == 0x0d && header[2] == 0x0d && header[3] == 0x0a;
            byte[] magic = null;
            if (section) {
                magic = readExact(4, false);
                if (Arrays.equals(magic, new byte[]{0x4d, 0x3c, 0x2b, 0x1a})) order = ByteOrder.LITTLE_ENDIAN;
                else if (Arrays.equals(magic, new byte[]{0x1a, 0x2b, 0x3c, 0x4d})) order = ByteOrder.BIG_ENDIAN;
                else throw invalid("Invalid pcapng byte-order magic");
            } else if (order == null) {
                throw invalid("Expected pcapng section header; classic pcap is unsupported");
            }
            ByteBuffer h = wrap(header);
            long type = unsigned(h.getInt());
            long length = unsigned(h.getInt());
            if (length < (section ? 28 : 12) || length % 4 != 0 || length > MAX_BLOCK_SIZE)
                throw invalid("Invalid or oversized pcapng block length: " + length);
            byte[] rest = readExact((int) length - (section ? 12 : 8), false);
            if (unsigned(wrap(rest).getInt(rest.length - 4)) != length)
                throw invalid("Pcapng block length trailer does not match header");
            byte[] bytes = new byte[(int) length - 12];
            if (section) {
                System.arraycopy(magic, 0, bytes, 0, 4);
                System.arraycopy(rest, 0, bytes, 4, rest.length - 4);
            } else System.arraycopy(rest, 0, bytes, 0, rest.length - 4);
            ByteBuffer body = wrap(bytes);
            CapturedFrame frame = null;
            if (section) {
                int major = Short.toUnsignedInt(body.getShort(4));
                if (major != 1) throw invalid("Unsupported pcapng major version: " + major);
                options(body, 16, (code, value) -> {});
                interfaces.clear();
                processes.clear();
                metadataBytes = 0;
                onReady.run();
            } else if (type == 1) {
                require(body, 8, "Truncated interface description");
                if (interfaces.size() >= MAX_TABLE_ENTRIES) throw invalid("Pcapng interface table limit reached");
                int linktype = Short.toUnsignedInt(body.getShort(0));
                String[] name = {""};
                double[] resolution = {1e-6};
                long[] offset = {0};
                options(body, 8, (code, value) -> {
                    if (code == 2) { name[0] = text(value, 128); metadataBytes += value.remaining(); }
                    else if (code == 9) {
                        numberLength(value, 1);
                        int raw = Byte.toUnsignedInt(value.get(0));
                        resolution[0] = (raw & 128) != 0 ? Math.scalb(1.0, -(raw & 127)) : Math.pow(10, -raw);
                    } else if (code == 14) { numberLength(value, 8); offset[0] = value.getLong(0); }
                });
                interfaces.add(new InterfaceInfo(linktype, name[0], resolution[0], offset[0]));
            } else if (type == 0x8000_0001L) {
                require(body, 4, "Truncated Apple process information block");
                if (processes.size() >= MAX_TABLE_ENTRIES) throw invalid("Pcapng process table limit reached");
                long raw = unsigned(body.getInt(0));
                Long pid = raw > 0 && raw <= Integer.MAX_VALUE ? raw : null;
                String[] name = {""};
                options(body, 4, (code, value) -> {
                    if (code == 2) { name[0] = text(value, 256); metadataBytes += value.remaining(); }
                });
                processes.add(new ProcessMetadata(pid, name[0]));
            } else if (type == 6) {
                frame = packet(body);
            } else if (type == 2 || type == 3) throw invalid("Only Enhanced Packet Blocks are supported");
            if (metadataBytes > MAX_METADATA_BYTES) throw invalid("Pcapng metadata memory limit reached");
            if (frame != null) return frame;
        }
    }

    private CapturedFrame packet(ByteBuffer body) throws IOException {
        require(body, 20, "Truncated enhanced packet block");
        long index = unsigned(body.getInt(0));
        long hi = unsigned(body.getInt(4)), lo = unsigned(body.getInt(8));
        long caplen = unsigned(body.getInt(12)), original = unsigned(body.getInt(16));
        long padded = (caplen + 3) & ~3L;
        if (caplen > original || 20 + padded > body.limit()) throw invalid("Invalid captured packet length");
        if (index >= interfaces.size()) throw invalid("Packet references an unknown interface");
        InterfaceInfo iface = interfaces.get((int) index);
        ProcessMetadata unknown = new ProcessMetadata(null, "");
        ProcessMetadata[] owner = {unknown, unknown};
        String[] direction = {"unknown"};
        options(body, (int) (20 + padded), (code, value) -> {
            if (code == 2) {
                numberLength(value, 4);
                direction[0] = switch (value.getInt(0) & 3) { case 1 -> "in"; case 2 -> "out"; default -> "unknown"; };
            } else if (code == 0x8001 || code == 0x8003) {
                numberLength(value, 4);
                long processIndex = unsigned(value.getInt(0));
                if (processIndex >= processes.size()) throw invalid("Packet references an unknown Apple process block");
                owner[code == 0x8001 ? 0 : 1] = processes.get((int) processIndex);
            }
        });
        double ticks = hi * 4_294_967_296.0 + lo;
        byte[] data = Arrays.copyOfRange(body.array(), 20, 20 + (int) caplen);
        return new CapturedFrame(ticks * iface.resolution + iface.offset, data, iface.linktype, original,
                owner[0].pid, owner[0].name, owner[1].pid, owner[1].name, iface.name, direction[0]);
    }

    private void options(ByteBuffer body, int offset, OptionVisitor visitor) throws IOException {
        while (offset < body.limit()) {
            if (body.limit() - offset < 4) throw invalid("Truncated pcapng option header");
            int code = Short.toUnsignedInt(body.getShort(offset));
            int length = Short.toUnsignedInt(body.getShort(offset + 2));
            offset += 4;
            int padded = (length + 3) & ~3;
            if (padded > body.limit() - offset) throw invalid("Pcapng option extends beyond its block");
            if (code == 0) {
                if (length != 0) throw invalid("Invalid end-of-options length");
                return;
            }
            visitor.accept(code, body.slice(offset, length).order(order));
            offset += padded;
        }
    }
    private static String text(ByteBuffer value, int maximum) throws IOException {
        if (value.remaining() > 4096) throw invalid("Pcapng metadata string exceeds 4096 bytes");
        byte[] bytes = new byte[value.remaining()];
        value.duplicate().get(bytes);
        int end = bytes.length;
        while (end > 0 && bytes[end - 1] == 0) end--;
        String text = new String(bytes, 0, end, StandardCharsets.UTF_8);
        if (text.codePointCount(0, text.length()) > maximum)
            throw invalid("Pcapng metadata name exceeds " + maximum + " characters");
        return text;
    }
    private static void numberLength(ByteBuffer value, int length) throws IOException {
        if (value.remaining() != length) throw invalid("Invalid numeric pcapng option length");
    }
    private static void require(ByteBuffer body, int length, String message) throws IOException {
        if (body.remaining() < length) throw invalid(message);
    }
    private byte[] readExact(int size, boolean eofOkay) throws IOException {
        byte[] bytes = new byte[size];
        int count = 0;
        while (count < size) {
            int read = stream.read(bytes, count, size - count);
            if (read < 0) {
                if (count == 0 && eofOkay) return null;
                throw invalid("Truncated pcapng block");
            }
            if (read == 0) {
                int one = stream.read();
                if (one < 0) {
                    if (count == 0 && eofOkay) return null;
                    throw invalid("Truncated pcapng block");
                }
                bytes[count++] = (byte) one;
            } else count += read;
        }
        return bytes;
    }
    private ByteBuffer wrap(byte[] bytes) { return ByteBuffer.wrap(bytes).order(order); }
    private static long unsigned(int value) { return Integer.toUnsignedLong(value); }
    private static IOException invalid(String message) { return new IOException(message); }
    @Override public void close() throws IOException { ended = true; stream.close(); }
}
