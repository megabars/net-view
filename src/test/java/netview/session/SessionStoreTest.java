package netview.session;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Consumer;
import static netview.protocol.PacketFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class SessionStoreTest {
    @TempDir Path directory;
    private final ObjectMapper json = new ObjectMapper();
    @Test void unsignedUnknownLinktypeSurvivesRoundTripWithoutWrappingIntoIpv4() throws Exception {
        Session session = new Session();
        byte[] raw = tcp("payload", 1, 24, false, 55L).data();
        var frame = new netview.model.CapturedFrame(1, raw, 0xffff_ffffL, raw.length, null, "", null, "", "", "");
        session.add(frame);
        Path file = directory.resolve("unknown.netview.json"); SessionStore.save(session, file); Session loaded = SessionStore.load(file);
        assertEquals(0xffff_ffffL, loaded.frames().getFirst().linktype());
        assertEquals("Unknown", loaded.packet(1).decoded().protocol());
        assertTrue(loaded.packet(1).decoded().issues().contains("Unsupported link type 4294967295"));
        assertArrayEquals(raw, loaded.packet(1).decoded().payload());
        assertEquals(frame, loaded.frames().getFirst());
    }
    @Test void pythonFixtureHasMatchingConnectionsAndStreamDigests() throws Exception {
        Session s = SessionStore.load(Path.of("tests/fixtures/lab_demo.netview.json"));
        assertEquals(20, s.packets().size()); assertEquals(6, s.connections().size()); assertEquals(1415, s.totalBytes());
        assertEquals(List.of(8L, 3L, 2L, 4L, 2L, 1L), s.connections().stream().map(c -> c.packetCount()).toList());
        String[][] hashes = {
                {"5aa4c123fc53944285b19eed3da068841c13a6452e27e9b9f8fdb0f34c671cd6", "504fdc7ba912a120ee018ee882ddbd7fb6aab12b67416ae2ca94379cc25b9963"},
                {"b5a5161877da9ada0707fa8786467f24f75dfd65b542c0d6c4f52c8814d86410"},
                {"b21fcad07ce8c247b9103fd471e521a6ea200bcf0b045b2dcefbb9ad9d7248be", "b21fcad07ce8c247b9103fd471e521a6ea200bcf0b045b2dcefbb9ad9d7248be"},
                {"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7"},
                {"d52397783bf4efbd17dc3fb6070c940ee490ff9070e91a66dd1abdeea0b7613d"},
                {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}};
        for (int i = 0; i < hashes.length; i++) {
            var streams = s.stream(i + 1); assertEquals(hashes[i].length, streams.size());
            for (int j = 0; j < hashes[i].length; j++) assertEquals(hashes[i][j], HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(streams.get(j).data())));
        }
    }
    @Test void roundTripPreservesOriginalBytesMetadataLimitsNotesAndStreams() throws Exception {
        Session s = new Session(3, 10000); s.notes().add("Capture queue dropped 12 frames; session is incomplete");
        s.add(tcp("", 1, 2, false, 55L)); s.add(tcp("\u0000ÿpayload", 2, 24, false, 55L)); s.add(tcp("answer", 10, 24, true, 55L));
        Path file = directory.resolve("capture.netview.json"); SessionStore.save(s, file); Session loaded = SessionStore.load(file);
        assertEquals(s.frames(), loaded.frames()); assertEquals(s.connections(), loaded.connections()); assertEquals(s.notes(), loaded.notes());
        assertEquals(s.totalBytes(), loaded.totalBytes()); assertEquals(s.maxBytes(), loaded.maxBytes()); assertEquals(s.maxPackets(), loaded.maxPackets());
        assertTrue(loaded.limitReached()); assertNull(loaded.add(tcp("", 1, 2, false, 55L)));
        for (int i = 0; i < s.stream(1).size(); i++) {
            assertArrayEquals(s.stream(1).get(i).data(), loaded.stream(1).get(i).data()); assertEquals(s.stream(1).get(i).issues(), loaded.stream(1).get(i).issues());
        }
        ObjectNode doc = (ObjectNode) json.readTree(file.toFile()); doc.remove("notes"); doc.remove("limit_reached"); json.writeValue(file.toFile(), doc);
        assertEquals(List.of(), SessionStore.load(file).notes());
    }
    @Test void strictTypesFieldsBase64AndCapBypassesAreRejected() throws Exception {
        Session s = new Session(); s.add(tcp("payload", 1, 24, false, 55L)); Path file = directory.resolve("capture.netview.json"); SessionStore.save(s, file);
        ObjectNode original = (ObjectNode) json.readTree(file.toFile());
        List<Consumer<ObjectNode>> changes = List.of(
                d -> d.put("version", true), d -> d.put("version", 1.0), d -> d.put("max_packets", 1_000_000_000_000L),
                d -> d.put("max_bytes", 1), d -> d.put("limit_reached", "yes"),
                d -> ((ObjectNode) d.get("frames").get(0)).put("data", "!invalid!"),
                d -> ((ObjectNode) d.get("frames").get(0)).put("pid", true),
                d -> ((ObjectNode) d.get("frames").get(0)).put("timestamp", "NaN"),
                d -> ((ObjectNode) d.get("frames").get(0)).put("process", "x".repeat(257)),
                d -> ((ObjectNode) d.get("frames").get(0)).put("extra", 1),
                d -> d.put("notes", "lost"), d -> d.putArray("notes").add("x".repeat(1025)),
                d -> { var a = d.putArray("notes"); for (int i = 0; i < 65; i++) a.add("x"); },
                d -> d.putArray("notes").addNull());
        for (Consumer<ObjectNode> change : changes) {
            ObjectNode changed = original.deepCopy(); change.accept(changed); json.writeValue(file.toFile(), changed);
            assertThrows(Exception.class, () -> SessionStore.load(file), changed.toString());
        }
        Files.writeString(file, "{\"format\":"); assertThrows(Exception.class, () -> SessionStore.load(file));
    }
    @Test void framesCanPrecedeHeaderAndFailedSavePreservesDestination() throws Exception {
        Path file = directory.resolve("capture.netview.json"); Session s = new Session(); s.add(tcp("payload", 1, 24, false, 55L)); SessionStore.save(s, file);
        ObjectNode doc = (ObjectNode) json.readTree(file.toFile()); JsonNode frames = doc.remove("frames");
        ObjectNode shuffled = json.createObjectNode(); shuffled.set("frames", frames); shuffled.setAll(doc); json.writeValue(file.toFile(), shuffled);
        assertEquals(s.frames(), SessionStore.load(file).frames());
        String before = Files.readString(file); for (int i = 0; i < 65; i++) s.notes().add("x");
        assertThrows(IllegalArgumentException.class, () -> SessionStore.save(s, file)); assertEquals(before, Files.readString(file));
    }
}
