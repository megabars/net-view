package netview.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import netview.capture.CaptureEvent;
import netview.capture.MacCaptureAdapter;
import netview.model.StreamPart;
import netview.session.Session;
import netview.session.SessionStore;

import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Headless entry points; capture readiness always comes from the native adapter. */
public final class SessionCli {
    private static final ObjectMapper JSON = new ObjectMapper();
    private SessionCli() {}

    public static int run(String[] args) {
        try {
            if (args.length == 2 && args[0].equals("--inspect")) {
                print(inspect(SessionStore.load(Path.of(args[1]))));
                return 0;
            }
            if (args.length > 0 && args[0].equals("--capture")) {
                Map<String, String> options = options(args);
                if (!options.keySet().containsAll(Set.of("--pid", "--output")))
                    throw new IllegalArgumentException("Usage: --capture --pid N [--seconds 3..60] --output PATH");
                long pid = Long.parseLong(options.get("--pid"));
                int seconds = Integer.parseInt(options.getOrDefault("--seconds", "10"));
                if (pid <= 0 || pid > Integer.MAX_VALUE || seconds < 3 || seconds > 60)
                    throw new IllegalArgumentException("PID must be positive; capture duration must be 3–60 seconds");
                return capture(pid, seconds, Path.of(options.get("--output")));
            }
            throw new IllegalArgumentException("Usage: --inspect FILE or --capture --pid N [--seconds 3..60] --output PATH");
        } catch (IOException | RuntimeException error) {
            try { print(Map.of("type", "error", "message", message(error))); }
            catch (IOException ignored) { System.err.println(message(error)); }
            return 2;
        }
    }
    private static Map<String, String> options(String[] args) {
        Map<String, String> options = new LinkedHashMap<>();
        for (int i = 1; i < args.length; i += 2) {
            if (i + 1 >= args.length || !Set.of("--pid", "--seconds", "--output").contains(args[i])
                    || options.putIfAbsent(args[i], args[i + 1]) != null)
                throw new IllegalArgumentException("Unknown, duplicate, or incomplete capture option");
        }
        return options;
    }
    public static Map<String, Object> inspect(Session session) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("packets", session.packets().size());
        result.put("connections", session.connections().size());
        result.put("raw_bytes", session.totalBytes());
        result.put("limit_reached", session.limitReached());
        result.put("notes", List.copyOf(session.notes()));
        Map<String, Object> hashes = new LinkedHashMap<>();
        for (var connection : session.connections()) {
            List<StreamPart> parts = session.stream(connection.id());
            for (int i = 0; i < parts.size(); i++) {
                StreamPart part = parts.get(i);
                byte[] data = part.data();
                hashes.put(connection.id() + ":" + i + ":" + part.name(),
                        Map.of("bytes", data.length, "sha256", sha256(data), "issues", part.issues()));
            }
        }
        result.put("stream_sha256", hashes);
        return result;
    }
    private static int capture(long pid, int seconds, Path output) throws IOException {
        Session session = new Session();
        List<String> errors = new ArrayList<>();
        long[] dropped = {0};
        Long[] kernelDropped = {null};
        boolean[] ready = {false};
        boolean stopping = false;
        boolean interrupted = false;
        MacCaptureAdapter adapter = new MacCaptureAdapter();
        Thread shutdown = new Thread(adapter::close, "netview-cli-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdown);
        long startupDeadline = System.nanoTime() + 10_000_000_000L;
        long captureDeadline = Long.MAX_VALUE, shutdownDeadline = Long.MAX_VALUE;
        try {
            adapter.start(Set.of(pid));
            while (true) {
                CaptureEvent event;
                long batchDeadline = System.nanoTime() + 12_000_000L;
                for (int batch = 0; batch < 128 && System.nanoTime() < batchDeadline
                        && (event = adapter.poll()) != null; batch++) {
                    switch (event.type()) {
                        case "ready" -> {
                            if (!ready[0] && !stopping) {
                                ready[0] = true;
                                captureDeadline = System.nanoTime() + seconds * 1_000_000_000L;
                                print(Map.of("type", "ready"));
                            }
                        }
                        case "packet" -> {
                            if (session.add(event.frame()) == null && !errors.contains("Session storage limit reached"))
                                errors.add("Session storage limit reached");
                        }
                        case "error" -> errors.add(event.message());
                        case "stats" -> { dropped[0] = event.dropped(); kernelDropped[0] = event.kernelDropped(); }
                        default -> { }
                    }
                }
                if (!adapter.running()) break;
                long now = System.nanoTime();
                if (!stopping && (!errors.isEmpty() || now >= captureDeadline || !ready[0] && now >= startupDeadline)) {
                    if (!ready[0] && errors.isEmpty()) errors.add("Capture did not become ready within 10 seconds");
                    adapter.stop(); stopping = true; shutdownDeadline = now + 6_000_000_000L;
                }
                if (stopping && now >= shutdownDeadline) { errors.add("Capture did not terminate within 6 seconds"); break; }
                Thread.sleep(10);
            }
        } catch (InterruptedException error) {
            interrupted = true;
            errors.add("Capture interrupted");
        } catch (RuntimeException error) {
            errors.add(message(error));
        } finally {
            adapter.close();
            CaptureEvent event;
            while ((event = adapter.poll()) != null) {
                if (event.type().equals("packet")) {
                    if (session.add(event.frame()) == null && !errors.contains("Session storage limit reached"))
                        errors.add("Session storage limit reached");
                } else if (event.type().equals("stats")) { dropped[0] = event.dropped(); kernelDropped[0] = event.kernelDropped(); }
                else if (event.type().equals("error")) errors.add(event.message());
            }
            try { Runtime.getRuntime().removeShutdownHook(shutdown); } catch (IllegalStateException ignored) { }
            if (interrupted) Thread.currentThread().interrupt();
        }
        if (!ready[0] && errors.isEmpty()) errors.add("Capture stopped before becoming ready");
        if (adapter.running()) errors.add("Capture worker remains active after close");
        session.notes().add("Java native macOS capture; selected PID " + pid + "; duration after readiness " + seconds + " seconds");
        session.notes().add("Adapter dropped=" + dropped[0] + "; kernel dropped=" + kernelDropped[0]);
        for (String error : errors) if (session.notes().size() < 64) session.notes().add(truncate("Capture error: " + error, 1024));
        try { SessionStore.save(session, output); }
        catch (IOException | RuntimeException error) { errors.add("Session save failed: " + message(error)); }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("type", "stopped"); summary.put("ready", ready[0]); summary.put("packets", session.packets().size());
        summary.put("dropped", dropped[0]); summary.put("kernel_dropped", kernelDropped[0]);
        summary.put("error", errors.isEmpty() ? null : String.join("\n", errors));
        summary.put("limit_reached", session.limitReached()); summary.put("output", output.toAbsolutePath().toString());
        print(summary);
        return errors.isEmpty() && dropped[0] == 0 && (kernelDropped[0] == null || kernelDropped[0] == 0) ? 0 : 1;
    }
    private static String truncate(String value, int maximum) {
        int count = value.codePointCount(0, value.length());
        return count <= maximum ? value : value.substring(0, value.offsetByCodePoints(0, maximum));
    }
    private static String sha256(byte[] data) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)); }
        catch (NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
    }
    private static String message(Exception error) { return error.getMessage() == null ? error.toString() : error.getMessage(); }
    private static void print(Object value) throws IOException { System.out.println(JSON.writeValueAsString(value)); System.out.flush(); }
}
