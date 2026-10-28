package netview.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SessionCliTest {
    @Test void inspectRealSessionPrintsCountsAndStreamHashes() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream previous = System.out;
        int status;
        try (PrintStream output = new PrintStream(buffer, true, StandardCharsets.UTF_8)) {
            System.setOut(output);
            status = SessionCli.run(new String[]{"--inspect", Path.of(
                    getClass().getResource("/parity/real-lab.netview.json").toURI()).toString()});
        } finally { System.setOut(previous); }
        assertEquals(0, status);
        var report = new ObjectMapper().readTree(buffer.toString(StandardCharsets.UTF_8));
        assertEquals(60, report.get("packets").asInt());
        assertEquals(4, report.get("connections").asInt());
        assertEquals(137062, report.get("raw_bytes").asInt());
        assertEquals(8, report.get("stream_sha256").size());
        report.get("stream_sha256").elements().forEachRemaining(part -> {
            assertEquals(64, part.get("sha256").asText().length());
            assertTrue(part.get("bytes").asInt() > 0);
        });
    }
    @Test void rejectsMalformedCaptureArgumentsBeforeLaunching() throws Exception {
        String[][] invalid = {
                {"--capture"}, {"--capture", "--pid", "0", "--output", "unused"},
                {"--capture", "--pid", "1", "--seconds", "2", "--output", "unused"},
                {"--capture", "--pid", "1", "--seconds", "61", "--output", "unused"},
                {"--capture", "--pid", "1", "--pid", "2", "--output", "unused"},
                {"--capture", "--pid", "1", "--unknown", "2", "--output", "unused"},
                {"--capture", "--pid", "1", "--output"}
        };
        PrintStream previous = System.out;
        try (PrintStream output = new PrintStream(new ByteArrayOutputStream())) {
            System.setOut(output);
            for (String[] arguments : invalid) assertEquals(2, SessionCli.run(arguments));
        } finally { System.setOut(previous); }
    }
}
