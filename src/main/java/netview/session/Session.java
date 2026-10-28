package netview.session;

import netview.model.*;
import netview.protocol.PacketDecoder;
import java.io.ByteArrayOutputStream;
import java.util.*;

/** Bounded session. Mutation (including add and notes) is thread confined; synchronize external access. */
public final class Session {
    public static final int MAX_PACKETS = 100_000;
    public static final long MAX_BYTES = 128L * 1024 * 1024;
    private final int maxPackets;
    private final long maxBytes;
    private long totalBytes;
    private boolean limitReached;
    private final List<SessionPacket> packets = new ArrayList<>();
    private final List<CapturedFrame> frames = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();
    private final Map<Long, State> connections = new LinkedHashMap<>();
    private final Map<Key, Long> active = new HashMap<>();

    public Session() { this(10_000, 32L * 1024 * 1024); }
    public Session(int maxPackets, long maxBytes) {
        if (maxPackets < 1 || maxPackets > MAX_PACKETS || maxBytes < 1 || maxBytes > MAX_BYTES)
            throw new IllegalArgumentException("Invalid session capture limits");
        this.maxPackets = maxPackets; this.maxBytes = maxBytes;
    }
    public SessionPacket add(CapturedFrame frame) {
        Objects.requireNonNull(frame, "frame");
        if (limitReached || packets.size() >= maxPackets || frame.capturedLength() > maxBytes - totalBytes) {
            limitReached = true; return null;
        }
        DecodedPacket p = PacketDecoder.decode(frame);
        Direction direction = direction(p);
        Endpoint a = new Endpoint(p.src(), p.sourcePort()), b = new Endpoint(p.dst(), p.destinationPort());
        if (a.compareTo(b) > 0) { Endpoint swap = a; a = b; b = swap; }
        Key key = new Key(p.protocol(), a, b, frame.pid(), frame.effectivePid());
        Long id = active.get(key);
        boolean syn = p.protocol().equals("TCP") && (p.tcpFlags() & 2) != 0 && (p.tcpFlags() & 16) == 0;
        Signature signature = syn ? new Signature(direction, p.tcpSequence()) : null;
        State state = id == null ? null : connections.get(id);
        if (state != null && syn) {
            if (state.closed || state.syn != null && !state.syn.equals(signature) || state.syn == null && state.observedDataOrFin) state = null;
            else if (state.syn == null) state.syn = signature;
        }
        if (state == null) {
            id = (long) connections.size() + 1;
            state = new State(id, p, signature); connections.put(id, state); active.put(key, id);
        }
        SessionPacket packet = new SessionPacket(packets.size() + 1L, state.id, p);
        String flow = frame.direction().toLowerCase(Locale.ROOT);
        boolean inbound = Set.of("in", "inbound", "incoming", "received").contains(flow);
        boolean outbound = Set.of("out", "outbound", "outgoing", "sent").contains(flow);
        if (inbound || !outbound && !direction.equals(state.direction)) state.receivedBytes += p.payloadLength();
        else state.sentBytes += p.payloadLength();
        if (p.protocol().equals("TCP")) {
            if ((p.tcpFlags() & 1) != 0) state.finDirections.add(direction);
            if ((p.tcpFlags() & 4) != 0 || state.finDirections.size() >= 2) state.closed = true;
        }
        state.observedDataOrFin |= p.payloadLength() > 0 || (p.tcpFlags() & 1) != 0;
        state.packets.add(packet); packets.add(packet); frames.add(frame);
        totalBytes += frame.capturedLength();
        if (packets.size() == maxPackets || totalBytes == maxBytes) limitReached = true;
        return packet;
    }
    public List<SessionPacket> packets() { return List.copyOf(packets); }
    public int packetCount() { return packets.size(); }
    public List<CapturedFrame> frames() { return List.copyOf(frames); }
    public List<Connection> connections() { return connections.values().stream().map(State::snapshot).toList(); }
    public List<SessionPacket> connectionPackets(long id) {
        State state = connections.get(id); return state == null ? List.of() : List.copyOf(state.packets);
    }
    public SessionPacket packet(long id) {
        if (id < 1 || id > packets.size()) throw new NoSuchElementException("Unknown packet " + id);
        return packets.get((int) id - 1);
    }
    public long totalBytes() { return totalBytes; }
    public boolean limitReached() { return limitReached; }
    public int maxPackets() { return maxPackets; }
    public long maxBytes() { return maxBytes; }
    /** Mutable capture diagnostics, validated to 64 notes of at most 1024 code points when saved. */
    public List<String> notes() { return notes; }
    void restoreLimitReached(boolean reached) { limitReached |= reached; }

    public List<StreamPart> stream(long id) {
        return reconstruct(connectionPackets(id));
    }

    /** Reconstruct an immutable packet snapshot independently of the mutable capture session. */
    public static List<StreamPart> reconstruct(List<SessionPacket> selected) {
        if (selected.isEmpty()) return List.of();
        String protocol = selected.getFirst().decoded().protocol();
        if (!protocol.equals("TCP")) return selected.stream().map(p -> new StreamPart(
                (protocol.equals("UDP") ? "Datagram #" : "Packet #") + p.id() + ": " + directionName(p.decoded()),
                p.decoded().payload(), p.decoded().issues())).toList();
        Map<Direction, List<DecodedPacket>> directions = new LinkedHashMap<>();
        for (SessionPacket packet : selected) directions.computeIfAbsent(direction(packet.decoded()), ignored -> new ArrayList<>()).add(packet.decoded());
        List<StreamPart> result = new ArrayList<>();
        for (List<DecodedPacket> directional : directions.values()) result.addAll(assembleTcp(directional));
        return List.copyOf(result);
    }

    private static List<StreamPart> assembleTcp(List<DecodedPacket> packets) {
        List<String> issues = new ArrayList<>();
        for (DecodedPacket p : packets) for (String issue : p.issues()) if (!issues.contains(issue)) issues.add(issue);
        List<DecodedPacket> valid = packets.stream().filter(p -> p.tcpSequence() != null).toList();
        String name = directionName(packets.getFirst());
        if (valid.isEmpty()) {
            issues.add("No valid TCP sequence numbers"); return List.of(new StreamPart(name, new byte[0], issues));
        }
        Optional<DecodedPacket> syn = valid.stream().filter(p -> (p.tcpFlags() & 2) != 0).findFirst();
        long anchor = syn.map(p -> (p.tcpSequence() + 1) & 0xffff_ffffL).orElse(valid.getFirst().tcpSequence());
        if (syn.isEmpty()) issues.add("Capture started without this direction's SYN; initial bytes may be missing");
        List<Segment> segments = new ArrayList<>();
        for (int i = 0; i < valid.size(); i++) {
            DecodedPacket p = valid.get(i); byte[] bytes = p.payload();
            if (bytes.length != 0) segments.add(new Segment(relative(p.tcpSequence() + ((p.tcpFlags() & 2) != 0 ? 1 : 0), anchor), i, bytes));
        }
        segments.sort(Comparator.comparingLong(Segment::start).thenComparingInt(Segment::index));
        List<Range> ranges = new ArrayList<>();
        Buffer current = null;
        long currentStart = 0, expected = syn.isPresent() || segments.isEmpty() ? 0 : segments.getFirst().start();
        int overlapCount = 0; boolean conflicting = false;
        for (Segment segment : segments) {
            long start = segment.start(); byte[] data = segment.data();
            if (current == null || start > expected) {
                if (current != null) ranges.add(new Range(currentStart, current.toByteArray()));
                if (start > expected) issues.add("TCP gap: " + (start - expected) + " missing bytes before relative sequence " + start + "; parts are not joined");
                current = new Buffer(); current.writeBytes(data); currentStart = start; expected = start + data.length;
                continue;
            }
            int overlap = (int) Math.min(data.length, expected - start);
            if (overlap != 0) {
                overlapCount++;
                int existingOffset = (int) (start - currentStart);
                for (int i = 0; i < overlap; i++) if (current.at(existingOffset + i) != data[i]) { conflicting = true; break; }
            }
            if (start + data.length > expected) { current.write(data, overlap, data.length - overlap); expected = start + data.length; }
        }
        if (current != null) ranges.add(new Range(currentStart, current.toByteArray()));
        if (overlapCount != 0) issues.add(overlapCount + " retransmitted/overlapping segments; overlapping bytes counted once");
        if (conflicting) issues.add("Conflicting overlapping TCP bytes; kept the segment with earlier sequence start (then earlier observation)");
        if (valid.stream().noneMatch(p -> (p.tcpFlags() & 5) != 0)) issues.add("No FIN/RST observed in this direction; stream end is not known to be complete");
        for (DecodedPacket p : valid) if ((p.tcpFlags() & 1) != 0) {
            long fin = relative(p.tcpSequence() + ((p.tcpFlags() & 2) != 0 ? 1 : 0) + p.payloadLength(), anchor);
            String issue = "TCP gap: " + (fin - expected) + " missing bytes before FIN";
            if (fin > expected && !issues.contains(issue)) issues.add(issue);
        }
        if (ranges.isEmpty()) return List.of(new StreamPart(name, new byte[0], issues));
        List<StreamPart> result = new ArrayList<>();
        for (int i = 0; i < ranges.size(); i++) {
            Range range = ranges.get(i);
            result.add(new StreamPart(ranges.size() == 1 ? name : name + " — part " + (i + 1) + " (relative sequence " + range.start() + ")", range.data(), issues));
        }
        return result;
    }
    private static long relative(long sequence, long anchor) { return (int) (sequence - anchor); }
    private static Direction direction(DecodedPacket p) { return new Direction(p.src(), p.sourcePort(), p.dst(), p.destinationPort()); }
    private static String endpoint(String address, Integer port) {
        String name = address.contains(":") ? "[" + address + "]" : address.isEmpty() ? "?" : address;
        return port == null ? name : name + ":" + port;
    }
    private static String directionName(DecodedPacket p) { return endpoint(p.src(), p.sourcePort()) + " → " + endpoint(p.dst(), p.destinationPort()); }
    private record Direction(String src, Integer sport, String dst, Integer dport) {}
    private record Endpoint(String address, Integer port) implements Comparable<Endpoint> {
        public int compareTo(Endpoint other) { int order = address.compareTo(other.address); return order != 0 ? order : Integer.compare(port == null ? -1 : port, other.port == null ? -1 : other.port); }
    }
    private record Key(String protocol, Endpoint a, Endpoint b, Long pid, Long effectivePid) {}
    private record Signature(Direction direction, Long sequence) {}
    private record Segment(long start, int index, byte[] data) {}
    private record Range(long start, byte[] data) {}
    private static final class Buffer extends ByteArrayOutputStream { byte at(int index) { return buf[index]; } }
    private static final class State {
        final long id; final DecodedPacket first; final Direction direction;
        final List<SessionPacket> packets = new ArrayList<>(); final Set<Direction> finDirections = new HashSet<>();
        Signature syn; boolean closed, observedDataOrFin; long sentBytes, receivedBytes;
        State(long id, DecodedPacket first, Signature syn) { this.id = id; this.first = first; this.direction = direction(first); this.syn = syn; }
        Connection snapshot() {
            CapturedFrame f = first.frame();
            return new Connection(id, directionName(first), first.protocol(), first.src(), first.dst(), first.sourcePort(), first.destinationPort(),
                    f.pid(), f.process(), f.effectivePid(), f.effectiveProcess(), packets.size(), sentBytes, receivedBytes);
        }
    }
}
