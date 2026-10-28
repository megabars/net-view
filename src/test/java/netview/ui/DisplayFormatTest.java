package netview.ui;

import netview.model.Connection;
import netview.model.StreamPart;
import netview.session.Session;
import netview.session.SessionStore;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Formatting contracts only: no native JavaFX window, permission request or traffic capture. */
class DisplayFormatTest {
    private static byte[] utf8(String text) { return text.getBytes(StandardCharsets.UTF_8); }

    @Test
    void formatsUnitsAndEndpointsWithoutConfusingIpv6Ports() {
        assertEquals("42 Б", DisplayFormat.size(42));
        assertEquals("1.0 КиБ", DisplayFormat.size(1024));
        assertEquals("1.0 МиБ", DisplayFormat.size(1024 * 1024));
        assertEquals("[::1]:443", DisplayFormat.endpoint("::1", 443));
        assertEquals("127.0.0.1", DisplayFormat.endpoint("127.0.0.1", null));
        assertEquals("Неизвестно", DisplayFormat.endpoint("", null));
    }

    @Test
    void preservesHexOffsetsAndDistinguishesBinaryTlsAndEmptyPayloads() {
        byte[] bytes = new byte[]{'H', 'i', 0, (byte) 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
        String hex = DisplayFormat.hex(bytes);
        assertTrue(hex.contains("000000"));
        assertTrue(hex.contains("48 69 00 ff"));
        assertTrue(hex.contains("Hi.."));
        assertTrue(hex.contains("000010"));
        assertEquals("Нет данных.", DisplayFormat.hex(new byte[0]));
        assertTrue(DisplayFormat.readable(new byte[]{(byte) 0xff, (byte) 0xfe}).contains("HEX"));
        assertTrue(DisplayFormat.readable(new byte[]{0, 1}).contains("Бинарные"));
        assertTrue(DisplayFormat.readable(new byte[0]).contains("Нет прикладных данных"));
        String tls = DisplayFormat.readable(new byte[]{23, 3, 3, 0, 5, 's', 'e', 'c', 'r', 't'});
        assertTrue(tls.contains("TLS"));
        assertTrue(tls.contains("не расшифровывается"));
        assertFalse(tls.contains("secrt"));
    }

    @Test
    void rendersUnicodeJsonHttpAndTheKnownLabLengthPrefix() {
        byte[] json = utf8("{\"message\":\"Привет\",\"value\":42}");
        String displayed = DisplayFormat.readable(json);
        assertTrue(displayed.contains("Привет"));
        assertTrue(displayed.contains("\"value\" : 42"));
        String http = DisplayFormat.readable(utf8("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + new String(json, StandardCharsets.UTF_8)));
        assertTrue(http.contains("HTTP/1.1 200 OK\nContent-Type"));
        assertTrue(http.contains("\"value\" : 42"));
        byte[] framed = ByteBuffer.allocate(4 + json.length).putInt(json.length).put(json).array();
        String framedText = DisplayFormat.readable(framed);
        assertTrue(framedText.toLowerCase().contains("префикс длины"));
        assertTrue(framedText.contains("Привет"));
    }

    @Test
    void doesNotEraseTrailingDataAfterAValidJsonPrefix() {
        for (String data : List.of("true trailing", "1 2", "{\"a\":1}junk", "   "))
            assertEquals(data, DisplayFormat.readable(utf8(data)), "Original text must remain visible: " + data);
        String pipelined = "HTTP/1.1 200 OK\r\n\r\n{\"a\":1}\r\nHTTP/1.1 200 OK\r\n\r\n{\"b\":2}";
        assertEquals(pipelined.replace("\r\n", "\n"), DisplayFormat.readable(utf8(pipelined)));
    }

    @Test
    void previewLimitIsExplicitAndDoesNotMutateOriginalBytes() {
        byte[] bytes = new byte[DisplayFormat.PREVIEW_LIMIT + 16];
        Arrays.fill(bytes, (byte) 'x');
        byte[] original = bytes.clone();
        String displayed = DisplayFormat.readable(bytes);
        assertTrue(displayed.contains(DisplayFormat.size(DisplayFormat.PREVIEW_LIMIT)));
        assertEquals(DisplayFormat.PREVIEW_LIMIT, displayed.chars().filter(c -> c == 'x').count());
        assertArrayEquals(original, bytes);
        String hex = DisplayFormat.hex(bytes);
        assertTrue(hex.contains("Предпросмотр ограничен"));
        assertFalse(hex.contains("040000"), "No hex row past the 256 KiB cap");
    }

    @Test
    void cappedLabFrameStillRecognizesTheOriginalLengthPrefix() {
        byte[] body = new byte[DisplayFormat.PREVIEW_LIMIT + 16];
        Arrays.fill(body, (byte) 'x');
        byte[] framed = ByteBuffer.allocate(4 + body.length).putInt(body.length).put(body).array();
        String displayed = DisplayFormat.readable(framed, 1024);
        assertTrue(displayed.toLowerCase().contains("префикс длины"));
        assertFalse(displayed.contains("Бинарные"));
        long shownBytes = displayed.chars().filter(c -> c == 'x').count();
        assertTrue(shownBytes > 0 && shownBytes <= 1024, "Bounded text preview remains visible");
        assertEquals(body.length + 4, framed.length);
    }

    @Test
    void gappedFixtureRemainsTwoSeparateReadablePartsWithWarnings() throws Exception {
        Path path = Path.of(getClass().getResource("/parity/synthetic-demo.netview.json").toURI());
        Session session = SessionStore.load(path);
        Connection connection = session.connections().stream().filter(c -> Integer.valueOf(50004).equals(c.sourcePort())).findFirst().orElseThrow();
        List<StreamPart> parts = session.stream(connection.id());
        assertEquals(2, parts.size());
        assertEquals("hello", DisplayFormat.readable(parts.get(0).data()));
        assertEquals("world", DisplayFormat.readable(parts.get(1).data()));
        assertNotEquals(parts.get(0).name(), parts.get(1).name());
        assertTrue(parts.stream().allMatch(part -> part.issues().stream().anyMatch(issue -> issue.contains("5 missing"))));
    }
}
