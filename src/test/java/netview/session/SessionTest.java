package netview.session;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.NoSuchElementException;
import static netview.protocol.PacketFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class SessionTest {
    private static String data(Session session, int part) { return new String(session.stream(1).get(part).data(), StandardCharsets.UTF_8); }
    @Test void immutableSnapshotCanBeReconstructedIndependentlyOfLaterCapture() {
        Session session = new Session();
        session.add(tcp("", 100, 2, false, 55L)); session.add(tcp("hello", 101, 24, false, 55L));
        var snapshot = session.connectionPackets(1);
        var expected = session.stream(1);
        session.add(tcp("world", 106, 24, false, 55L));
        var reconstructed = Session.reconstruct(snapshot);
        assertEquals(expected.size(), reconstructed.size());
        for (int i = 0; i < expected.size(); i++) {
            assertEquals(expected.get(i).name(), reconstructed.get(i).name());
            assertEquals(expected.get(i).issues(), reconstructed.get(i).issues());
            assertArrayEquals(expected.get(i).data(), reconstructed.get(i).data());
        }
        assertEquals("helloworld", data(session, 0));
        assertEquals("hello", new String(reconstructed.getFirst().data(), StandardCharsets.UTF_8));
        assertTrue(Session.reconstruct(java.util.List.of()).isEmpty());
    }
    @Test void reorderedRetransmissionAndCounters() {
        Session s = new Session();
        s.add(tcp("", 100, 2, false, 55L)); s.add(tcp("world", 106, 24, false, 55L));
        s.add(tcp("hello", 101, 24, false, 55L)); s.add(tcp("hello", 101, 24, false, 55L));
        s.add(tcp("", 111, 17, false, 55L)); s.add(tcp("response", 500, 24, true, 55L));
        assertEquals(1, s.connections().size()); var c = s.connections().getFirst();
        assertEquals(6, c.packetCount()); assertEquals(15, c.sentBytes()); assertEquals(8, c.receivedBytes());
        assertEquals("helloworld", data(s, 0)); assertEquals("response", data(s, 1));
        assertTrue(s.stream(1).getFirst().issues().stream().anyMatch(i -> i.contains("overlapping")));
        assertFalse(s.stream(1).getFirst().issues().stream().anyMatch(i -> i.contains("gap")));
        assertEquals(5, s.packet(3).decoded().payloadLength()); assertEquals(6, s.connectionPackets(1).size());
    }
    @Test void gapsPrefixAndTailRemainExplicit() {
        Session s = new Session(); s.add(tcp("", 100, 2, false, 55L)); s.add(tcp("one", 104, 24, false, 55L));
        s.add(tcp("two", 111, 24, false, 55L)); s.add(tcp("", 120, 17, false, 55L));
        assertEquals("one", data(s, 0)); assertEquals("two", data(s, 1));
        for (String text : new String[]{"3 missing", "4 missing", "6 missing bytes before FIN"})
            assertTrue(s.stream(1).getFirst().issues().stream().anyMatch(i -> i.contains(text)), text);
    }
    @Test void wrapOverlapConflictAndMidstream() {
        Session s = new Session(); s.add(tcp("", 0xfffffffcL, 2, false, 55L)); s.add(tcp("def", 0, 24, false, 55L)); s.add(tcp("abcd", 0xfffffffdL, 24, false, 55L));
        assertEquals("abcdef", data(s, 0)); assertTrue(s.stream(1).getFirst().issues().stream().noneMatch(i -> i.contains("gap")));
        s = new Session(); s.add(tcp("abc", 10, 24, false, 55L)); s.add(tcp("XYZ", 11, 24, false, 55L));
        assertEquals("abcZ", data(s, 0)); String issues = String.join(" ", s.stream(1).getFirst().issues());
        assertTrue(issues.contains("Conflicting")); assertTrue(issues.contains("without")); assertTrue(issues.contains("end"));
    }
    @Test void synTupleReuseAndPidIsolation() {
        Session s = new Session(); s.add(tcp("", 1, 2, false, 55L)); s.add(tcp("", 1, 2, false, 55L));
        s.add(tcp("x", 2, 24, false, 55L)); s.add(tcp("", 100, 2, false, 55L));
        s.add(tcp("unknown", 10, 24, false, null)); s.add(tcp("other", 10, 24, false, 999L));
        assertEquals(java.util.List.of(3L, 1L, 1L, 1L), s.connections().stream().map(c -> c.packetCount()).toList());
        assertNull(s.connections().get(2).pid());
        s = new Session(); s.add(tcp("", 500, 18, true, 55L)); s.add(tcp("", 100, 2, false, 55L));
        assertEquals(1, s.connections().size()); s.add(tcp("", 101, 17, false, 55L)); s.add(tcp("", 501, 17, true, 55L)); s.add(tcp("", 100, 2, false, 55L));
        assertEquals(java.util.List.of(4L, 1L), s.connections().stream().map(c -> c.packetCount()).toList());
    }
    @Test void udpAndLimitsAndImmutability() {
        Session s = new Session(2, 1000); var f = frame(new byte[]{1}, 0, 0, false, 55L, true);
        s.add(f); s.add(f); assertTrue(s.limitReached()); assertNull(s.add(f)); assertEquals(2, s.stream(1).size());
        assertTrue(s.stream(1).getFirst().name().contains("Datagram")); assertThrows(UnsupportedOperationException.class, () -> s.frames().clear());
        assertThrows(NoSuchElementException.class, () -> s.packet(0));
        Session bytes = new Session(10, f.capturedLength()); bytes.add(f); assertTrue(bytes.limitReached()); assertNull(bytes.add(f));
        Session tiny = new Session(10, 1); assertNull(tiny.add(f)); assertEquals(0, tiny.totalBytes()); assertTrue(tiny.limitReached());
        assertThrows(IllegalArgumentException.class, () -> new Session(100001, 10)); assertThrows(IllegalArgumentException.class, () -> new Session(1, 0));
    }
}
