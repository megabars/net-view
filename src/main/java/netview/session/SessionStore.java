package netview.session;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import netview.model.CapturedFrame;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Python-compatible v1 persistence, strict metadata validation and bounded streaming I/O. */
public final class SessionStore {
    public static final long MAX_FILE_BYTES = 320L * 1024 * 1024;
    private static final String FORMAT = "netview-session";
    private static final Set<String> FRAME_FIELDS = Set.of("timestamp", "data", "linktype", "original_length", "pid", "process", "effective_pid", "effective_process", "interface", "direction");
    private static final JsonFactory FACTORY = JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(100)
                    .maxStringLength((int) (((Session.MAX_BYTES + 2) / 3) * 4)).build())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();
    private static final ObjectMapper JSON = new ObjectMapper(FACTORY);
    private SessionStore() {}

    public static Session load(Path source) throws IOException {
        if (Files.size(source) > MAX_FILE_BYTES) throw invalid("Session file exceeds the safety limit");
        Map<String, JsonNode> header = new HashMap<>();
        // Two streaming passes accept any property order without retaining a document of base64 frames.
        try (JsonParser parser = parser(source)) {
            require(parser.nextToken() == JsonToken.START_OBJECT, "Not a Net View session");
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                require(parser.currentToken() == JsonToken.FIELD_NAME, "Invalid session JSON");
                String name = parser.currentName(); parser.nextToken();
                if (name.equals("frames")) {
                    require(parser.currentToken() == JsonToken.START_ARRAY, "Invalid session frames");
                    header.put(name, JSON.getNodeFactory().booleanNode(true)); parser.skipChildren();
                } else if (Set.of("format", "version", "max_packets", "max_bytes", "limit_reached", "notes").contains(name)) {
                    header.put(name, JSON.readTree(parser));
                } else parser.skipChildren();
            }
            require(parser.nextToken() == null, "Trailing session JSON");
        }
        require(FORMAT.equals(text(header.get("format"), "format", 32)), "Not a Net View session");
        require(integer(header.get("version"), "version", 1, 1) == 1, "Unsupported session version");
        Session session = new Session((int) integer(header.get("max_packets"), "max_packets", 1, Session.MAX_PACKETS),
                integer(header.get("max_bytes"), "max_bytes", 1, Session.MAX_BYTES));
        boolean limited = false;
        if (header.containsKey("limit_reached")) {
            require(header.get("limit_reached").isBoolean(), "Invalid session limit state"); limited = header.get("limit_reached").booleanValue();
        }
        if (header.containsKey("notes")) {
            JsonNode notes = header.get("notes"); require(notes.isArray() && notes.size() <= 64, "Invalid session notes");
            for (JsonNode note : notes) session.notes().add(text(note, "session note", 1024));
        }
        require(header.containsKey("frames"), "Invalid session frames");
        int frameCount = 0;
        try (JsonParser parser = parser(source)) {
            require(parser.nextToken() == JsonToken.START_OBJECT, "Invalid session JSON");
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                require(parser.currentToken() == JsonToken.FIELD_NAME, "Invalid session JSON");
                String name = parser.currentName(); parser.nextToken();
                if (!name.equals("frames")) { parser.skipChildren(); continue; }
                require(parser.currentToken() == JsonToken.START_ARRAY, "Invalid session frames");
                while (parser.nextToken() != JsonToken.END_ARRAY) {
                    require(frameCount++ < session.maxPackets(), "Invalid session frame count");
                    require(parser.currentToken() == JsonToken.START_OBJECT, "Invalid frame fields");
                    Map<String, JsonNode> fields = new HashMap<>();
                    while (parser.nextToken() != JsonToken.END_OBJECT) {
                        require(parser.currentToken() == JsonToken.FIELD_NAME && FRAME_FIELDS.contains(parser.currentName()), "Invalid frame fields");
                        String field = parser.currentName(); parser.nextToken();
                        require(parser.currentToken().isScalarValue(), "Invalid frame metadata");
                        fields.put(field, JSON.readTree(parser));
                    }
                    require(fields.keySet().equals(FRAME_FIELDS), "Invalid frame fields");
                    long remaining = session.maxBytes() - session.totalBytes();
                    String encoded = text(fields.get("data"), "frame data", (int) (((remaining + 2) / 3) * 4));
                    byte[] data;
                    try { data = strictBase64(encoded); }
                    catch (IllegalArgumentException error) { throw new IllegalArgumentException("Invalid frame base64", error); }
                    require(data.length <= remaining, "Session exceeds the captured byte limit");
                    JsonNode timestamp = fields.get("timestamp");
                    require(timestamp.isNumber() && Double.isFinite(timestamp.doubleValue()), "Invalid timestamp");
                    CapturedFrame frame = new CapturedFrame(timestamp.doubleValue(), data,
                            integer(fields.get("linktype"), "linktype", 0, 0xffff_ffffL),
                            integer(fields.get("original_length"), "original_length", 0, 0xffff_ffffL),
                            pid(fields.get("pid")), text(fields.get("process"), "process", 256),
                            pid(fields.get("effective_pid")), text(fields.get("effective_process"), "effective_process", 256),
                            text(fields.get("interface"), "interface", 128), text(fields.get("direction"), "direction", 32));
                    require(session.add(frame) != null, "Session exceeds its capture limits");
                }
            }
            require(parser.nextToken() == null, "Trailing session JSON");
        }
        session.restoreLimitReached(limited);
        return session;
    }

    public static void save(Session session, Path destination) throws IOException {
        List<String> notes = new ArrayList<>(session.notes());
        require(notes.size() <= 64, "Invalid session notes");
        for (String note : notes) require(note != null && note.codePointCount(0, note.length()) <= 1024, "Invalid session note");
        Path absolute = destination.toAbsolutePath(), temporary = Files.createTempFile(absolute.getParent(), "." + absolute.getFileName() + ".", ".tmp");
        try {
            try (JsonGenerator output = FACTORY.createGenerator(Files.newOutputStream(temporary))) {
                output.writeStartObject(); output.writeStringField("format", FORMAT); output.writeNumberField("version", 1);
                output.writeNumberField("max_packets", session.maxPackets()); output.writeNumberField("max_bytes", session.maxBytes());
                output.writeBooleanField("limit_reached", session.limitReached());
                output.writeArrayFieldStart("notes"); for (String note : notes) output.writeString(note); output.writeEndArray();
                output.writeArrayFieldStart("frames");
                for (CapturedFrame frame : session.frames()) {
                    output.writeStartObject(); output.writeNumberField("timestamp", frame.timestamp()); output.writeBinaryField("data", frame.data());
                    output.writeNumberField("linktype", frame.linktype()); output.writeNumberField("original_length", frame.originalLength());
                    writePid(output, "pid", frame.pid()); output.writeStringField("process", frame.process());
                    writePid(output, "effective_pid", frame.effectivePid()); output.writeStringField("effective_process", frame.effectiveProcess());
                    output.writeStringField("interface", frame.networkInterface()); output.writeStringField("direction", frame.direction()); output.writeEndObject();
                }
                output.writeEndArray(); output.writeEndObject(); output.writeRaw('\n');
            }
            require(Files.size(temporary) <= MAX_FILE_BYTES, "Session file exceeds the safety limit");
            // Fail without replacing the destination if its filesystem cannot provide atomic replacement.
            Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temporary); }
    }
    private static void writePid(JsonGenerator output, String name, Long pid) throws IOException {
        if (pid == null) output.writeNullField(name); else output.writeNumberField(name, pid);
    }
    private static JsonParser parser(Path source) throws IOException {
        return FACTORY.createParser(new BoundedInputStream(Files.newInputStream(source)));
    }
    private static Long pid(JsonNode value) { return value.isNull() ? null : integer(value, "pid", 0, Integer.MAX_VALUE); }
    private static long integer(JsonNode value, String name, long min, long max) {
        require(value != null && value.isIntegralNumber() && value.canConvertToLong(), "Invalid " + name);
        long number = value.longValue(); require(number >= min && number <= max, "Invalid " + name); return number;
    }
    private static String text(JsonNode value, String name, int max) {
        require(value != null && value.isTextual(), "Invalid " + name); String text = value.textValue();
        require(text.codePointCount(0, text.length()) <= max, "Invalid " + name); return text;
    }
    private static byte[] strictBase64(String encoded) {
        // Java's decoder accepts omitted padding; Python's validate=True requires complete quartets.
        require(encoded.length() % 4 == 0, "Invalid frame base64");
        return Base64.getDecoder().decode(encoded);
    }
    private static void require(boolean condition, String message) { if (!condition) throw invalid(message); }
    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
    private static final class BoundedInputStream extends FilterInputStream {
        private long count;
        BoundedInputStream(InputStream input) { super(input); }
        private void counted(int amount) throws IOException { if (amount > 0 && (count += amount) > MAX_FILE_BYTES) throw new IOException("Session file exceeds the safety limit"); }
        @Override public int read() throws IOException { int value = super.read(); if (value != -1) counted(1); return value; }
        @Override public int read(byte[] buffer, int offset, int length) throws IOException { int count = in.read(buffer, offset, length); counted(count); return count; }
        @Override public long skip(long count) throws IOException { long skipped = in.skip(count); this.count += skipped; if (this.count > MAX_FILE_BYTES) throw new IOException("Session file exceeds the safety limit"); return skipped; }
    }
}
