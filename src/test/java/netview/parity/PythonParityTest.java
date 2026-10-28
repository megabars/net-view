package netview.parity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import netview.model.CapturedFrame;
import netview.model.Connection;
import netview.model.DecodedPacket;
import netview.model.SessionPacket;
import netview.model.StreamPart;
import netview.session.Session;
import netview.session.SessionStore;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Committed Python outputs are an independent oracle; this test does not invoke Python. */
class PythonParityTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final List<String> FIXTURES = List.of("synthetic-demo", "synthetic-stress", "real-lab");

    @Test
    void decodesAndReconstructsEveryPythonFixtureAndRoundTripsJavaFiles() throws Exception {
        Path javaOutput = Path.of("target/parity-java");
        Files.createDirectories(javaOutput);
        for (String name : FIXTURES) {
            Path input = Path.of(getClass().getResource("/parity/" + name + ".netview.json").toURI());
            JsonNode document = JSON.readTree(getClass().getResourceAsStream("/parity/" + name + ".expected.json"));
            assertEquals(document.path("source_sha256").asText(), sha(Files.readAllBytes(input)), name + " source integrity");
            Session session = SessionStore.load(input);
            assertJson(document.get("expected"), manifest(session), name);
            Path output = javaOutput.resolve(name + ".netview.json");
            SessionStore.save(session, output);
            Session roundTrip = SessionStore.load(output);
            assertEquals(session.frames(), roundTrip.frames(), name + " original frame metadata and bytes");
            assertJson(document.get("expected"), manifest(roundTrip), name + " Java round trip");
            // Files remain in target/parity-java for the independent Python read-back command.
        }
    }

    private static JsonNode manifest(Session session) throws Exception {
        List<Map<String, Object>> packets = new ArrayList<>();
        for (SessionPacket value : session.packets()) {
            DecodedPacket packet = value.decoded();
            CapturedFrame frame = packet.frame();
            Map<String, Object> item = map("id", value.id(), "connection_id", value.connectionId(),
                    "src", packet.src(), "dst", packet.dst(), "sport", packet.sourcePort(),
                    "dport", packet.destinationPort(), "protocol", packet.protocol(),
                    "tcp_seq", packet.tcpSequence(), "tcp_flags", packet.tcpFlags(),
                    "wire_length", packet.wireLength(), "payload_length", packet.payloadLength(),
                    "payload_sha256", sha(packet.payload()), "raw_sha256", sha(frame.data()),
                    "captured_length", frame.capturedLength(), "issue_count", packet.issues().size(),
                    "issue_kinds", issueKinds(packet.issues()));
            item.put("frame", map("timestamp", frame.timestamp(), "linktype", frame.linktype(),
                    "original_length", frame.originalLength(), "pid", frame.pid(), "process", frame.process(),
                    "effective_pid", frame.effectivePid(), "effective_process", frame.effectiveProcess(),
                    "interface", frame.networkInterface(), "direction", frame.direction()));
            packets.add(item);
        }
        List<Map<String, Object>> connections = new ArrayList<>();
        List<Map<String, Object>> streams = new ArrayList<>();
        for (Connection connection : session.connections()) {
            connections.add(map("id", connection.id(), "label", connection.label(), "protocol", connection.protocol(),
                    "src", connection.src(), "dst", connection.dst(), "sport", connection.sourcePort(),
                    "dport", connection.destinationPort(), "pid", connection.pid(), "process", connection.process(),
                    "effective_pid", connection.effectivePid(), "effective_process", connection.effectiveProcess(),
                    "packet_count", connection.packetCount(), "sent_bytes", connection.sentBytes(),
                    "received_bytes", connection.receivedBytes()));
            assertEquals(connection.packetCount(), session.connectionPackets(connection.id()).size(), "connection packet lookup");
            for (StreamPart part : session.stream(connection.id())) {
                streams.add(map("connection_id", connection.id(), "name", part.name(), "length", part.length(),
                        "sha256", sha(part.data()), "issue_count", part.issues().size(), "issue_kinds", issueKinds(part.issues())));
            }
        }
        return JSON.valueToTree(map("packet_count", packets.size(), "connection_count", connections.size(),
                "total_bytes", session.totalBytes(), "max_packets", session.maxPackets(), "max_bytes", session.maxBytes(),
                "limit_reached", session.limitReached(), "notes", session.notes(), "packets", packets,
                "connections", connections, "streams", streams));
    }

    private static List<String> issueKinds(List<String> issues) {
        return issues.stream().map(issue -> {
            String text = issue.toLowerCase(Locale.ROOT);
            if (text.contains("gap")) return "gap";
            if (text.contains("conflict")) return "conflict";
            if (text.contains("overlap") || text.contains("retransmit")) return "overlap";
            if (text.contains("without") && text.contains("syn")) return "missing-syn";
            if (text.contains("fin/rst") || text.contains("stream end")) return "unknown-end";
            if (text.contains("truncat")) return "truncated";
            if (text.contains("fragment")) return "fragment";
            if (text.contains("malformed")) return "malformed";
            if (text.contains("unsupported")) return "unsupported";
            if (text.contains("limit")) return "limit";
            return "other";
        }).toList();
    }

    private static Map<String, Object> map(Object... entries) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) result.put((String) entries[i], entries[i + 1]);
        return result;
    }

    private static String sha(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    private static void assertJson(JsonNode expected, JsonNode actual, String location) {
        assertNotNull(actual, location);
        if (expected.isNumber() && actual.isNumber()) {
            assertEquals(0, expected.decimalValue().compareTo(actual.decimalValue()), location + " numeric value");
        } else if (expected.isObject() && actual.isObject()) {
            assertEquals(expected.size(), actual.size(), location + " field count");
            expected.fieldNames().forEachRemaining(key -> assertJson(expected.get(key), actual.get(key), location + "." + key));
        } else if (expected.isArray() && actual.isArray()) {
            assertEquals(expected.size(), actual.size(), location + " item count");
            for (int i = 0; i < expected.size(); i++) assertJson(expected.get(i), actual.get(i), location + "[" + i + "]");
        } else {
            assertEquals(expected, actual, location);
        }
    }
}
