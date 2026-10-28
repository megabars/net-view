package netview.capture;

import netview.model.CapturedFrame;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** Normal-user GUI backend; only the native tcpdump child receives elevated privileges. */
public final class MacCaptureAdapter implements CaptureAdapter {
    public static final int MAX_QUEUE_EVENTS = 2_000;
    public static final long MAX_QUEUE_BYTES = 32L * 1024 * 1024;
    private static final int CONTROL_RESERVE = 16;
    private static final Pattern KERNEL_DROPS = Pattern.compile("(\\d+) packets? dropped by kernel");
    @FunctionalInterface interface ProcessLauncher { Process launch(List<String> command) throws IOException; }
    private final ProcessLauncher launcher;
    private final boolean mac;
    private final Deque<CaptureEvent> events = new ArrayDeque<>();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final AtomicBoolean ready = new AtomicBoolean();
    private final Object terminationLock = new Object();
    private volatile Thread worker;
    private volatile Process process;
    private volatile Long kernelDropped;
    private long packetBytes;
    private long dropped;
    private boolean closed;

    public MacCaptureAdapter() {
        this(command -> new ProcessBuilder(command).redirectInput(ProcessBuilder.Redirect.from(
                new java.io.File("/dev/null"))).start(),
                System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("mac"));
    }
    MacCaptureAdapter(ProcessLauncher launcher, boolean mac) { this.launcher = launcher; this.mac = mac; }

    @Override public synchronized void start(Set<Long> pids) {
        if (closed) throw new IllegalStateException("Capture adapter is closed");
        if (running()) throw new IllegalStateException("Capture is already running");
        if (pids == null || pids.isEmpty() || pids.size() > 256
                || pids.stream().anyMatch(pid -> pid == null || pid <= 0 || pid > Integer.MAX_VALUE))
            throw new IllegalArgumentException("Select 1–256 positive numeric process IDs");
        Set<Long> selection = Set.copyOf(pids);
        synchronized (events) { events.clear(); packetBytes = 0; dropped = 0; }
        kernelDropped = null;
        cancelled.set(false);
        ready.set(false);
        worker = new Thread(() -> run(selection), "netview-capture");
        worker.setDaemon(true);
        worker.start();
    }
    @Override public void stop() {
        cancelled.set(true);
        Process active = process;
        if (active != null) {
            // Destroying first releases a blocking ProcessPipeInputStream read. Closing that
            // stream directly on the UI thread can wait on the reader's internal monitor.
            Thread terminator = new Thread(() -> terminate(active), "netview-capture-stop");
            terminator.setDaemon(true);
            terminator.start();
        }
    }
    @Override public boolean running() { Thread active = worker; return active != null && active.isAlive(); }
    @Override public CaptureEvent poll() {
        synchronized (events) {
            CaptureEvent event = events.pollFirst();
            if (event != null && event.frame() != null) packetBytes -= event.frame().capturedLength();
            return event;
        }
    }
    @Override public void close() {
        synchronized (this) { closed = true; }
        stop();
        Thread active = worker;
        if (active != null && active != Thread.currentThread()) {
            try { active.join(Duration.ofSeconds(6).toMillis()); }
            catch (InterruptedException exc) { Thread.currentThread().interrupt(); }
        }
    }

    static List<String> command(Set<Long> pids, String username) {
        String expression = pids.stream().sorted().map(pid -> "pid=" + pid + " or epid=" + pid)
                .reduce((left, right) -> left + " or " + right).orElseThrow();
        return List.of("/usr/bin/sudo", "-n", "/usr/sbin/tcpdump", "-i", "pktap,all", "-s", "0", "-U",
                "-P", "-w", "-", "-Q", "(" + expression + ")", "-Z", username, "ip or ip6");
    }
    private void run(Set<Long> pids) {
        Process child = null;
        Thread stderr = null;
        Deque<String> tail = new ArrayDeque<>();
        String failure = null;
        try {
            if (!mac) throw new IOException("Live capture requires macOS with Apple's tcpdump; saved sessions remain available");
            String user = ProcessHandle.current().info().user()
                    .orElseThrow(() -> new IOException("Cannot determine the current operating-system user"));
            if (user.isBlank() || user.equals("root"))
                throw new IOException("Launch Net View as your normal user from Terminal after sudo -v");
            if (cancelled.get()) return;
            child = launcher.launch(command(pids, user));
            process = child;
            Process owned = child;
            stderr = new Thread(() -> drainStderr(owned.getErrorStream(), tail), "netview-capture-stderr");
            stderr.setDaemon(true);
            stderr.start();
            // stop() may have raced with process assignment. Start the bounded
            // terminator, but still read stdout until its writers actually exit.
            if (cancelled.get()) stop();
            long lastStats = System.nanoTime();
            try (PcapngReader reader = new PcapngReader(child.getInputStream(), this::markReady)) {
                CapturedFrame frame;
                while ((frame = reader.next()) != null) {
                    // tcpdump may flush packet blocks before printing final stats.
                    // Closing stdout on cancellation would give that flush SIGPIPE,
                    // losing diagnostics. The separate terminator bounds this drain.
                    if (cancelled.get()) continue;
                    if ((frame.pid() != null && pids.contains(frame.pid()))
                            || (frame.effectivePid() != null && pids.contains(frame.effectivePid())))
                        emit(new CaptureEvent("packet", frame, "", 0, null));
                    if (System.nanoTime() - lastStats >= 1_000_000_000L) { stats(); lastStats = System.nanoTime(); }
                }
            }
            if (!cancelled.get()) failure = "Capture stream ended unexpectedly";
        } catch (IOException | RuntimeException exc) {
            if (!cancelled.get()) failure = exc.getMessage() == null ? exc.toString() : exc.getMessage();
        } finally {
            if (child != null) {
                boolean stopped = terminate(child);
                if (!stopped) failure = "Capture subprocess did not stop; check Terminal";
                if (stderr != null) {
                    try { stderr.join(500); }
                    catch (InterruptedException exc) { Thread.currentThread().interrupt(); }
                }
                if (stderr == null || !stderr.isAlive()) closeQuietly(child.getErrorStream());
                process = null;
            }
            if (failure != null) {
                String diagnostic;
                synchronized (tail) { diagnostic = String.join("\n", tail); }
                String message = failure + (diagnostic.isEmpty() ? "" : "\n" + diagnostic);
                String lower = diagnostic.toLowerCase(Locale.ROOT);
                if (lower.contains("password") || lower.contains("sudo:"))
                    message += "\nAuthenticate in Terminal with sudo -v, then launch the app from that same Terminal. The app never requests a password.";
                emit(new CaptureEvent("error", null, message, 0, null));
            }
            stats();
            emit(CaptureEvent.control("stopped"));
        }
    }
    void emit(CaptureEvent event) {
        synchronized (events) {
            // Keep only the newest cumulative snapshot; unattended capture must not
            // fill its reserved control slots with obsolete once-per-second stats.
            if (event.type().equals("stats")) events.removeIf(queued -> queued.type().equals("stats"));
            if (event.type().equals("packet")) {
                int size = event.frame().capturedLength();
                if (events.size() >= MAX_QUEUE_EVENTS - CONTROL_RESERVE || packetBytes + size > MAX_QUEUE_BYTES) {
                    dropped++;
                    return;
                }
                packetBytes += size;
            } else if (events.size() >= MAX_QUEUE_EVENTS) {
                CaptureEvent removed = events.removeFirst();
                if (removed.frame() != null) { packetBytes -= removed.frame().capturedLength(); dropped++; }
            }
            if (event.type().equals("stats")) event = new CaptureEvent("stats", null, "", dropped, kernelDropped);
            events.addLast(event);
        }
    }
    private void markReady() { if (ready.compareAndSet(false, true)) emit(CaptureEvent.control("ready")); }
    void stats() {
        synchronized (events) { emit(new CaptureEvent("stats", null, "", dropped, kernelDropped)); }
    }
    private void drainStderr(InputStream pipe, Deque<String> tail) {
        byte[] chunk = new byte[2048];
        StringBuilder line = new StringBuilder();
        try {
            int count;
            while ((count = pipe.read(chunk)) >= 0) {
                for (int i = 0; i < count; i++) {
                    int b = Byte.toUnsignedInt(chunk[i]);
                    if (b == '\n' || line.length() >= 4096) {
                        stderrLine(line.toString(), tail);
                        line.setLength(0);
                    }
                    if (b != '\n') line.append((char) b);
                }
            }
        } catch (IOException ignored) {
            // Closed by shutdown; any complete diagnostics already remain in the bounded tail.
        } finally { if (!line.isEmpty()) stderrLine(line.toString(), tail); }
    }
    private void stderrLine(String raw, Deque<String> tail) {
        String line = new String(raw.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8).strip();
        synchronized (tail) { if (tail.size() == 16) tail.removeFirst(); tail.addLast(line); }
        if (line.contains("listening on ")) markReady();
        var match = KERNEL_DROPS.matcher(line);
        if (match.find()) {
            try { kernelDropped = Long.parseLong(match.group(1)); }
            catch (NumberFormatException ignored) { /* Keep unavailable instead of fabricating a count. */ }
        }
    }

    private boolean terminate(Process child) {
        synchronized (terminationLock) {
            // Keep actual child handles before terminating sudo, so reparenting cannot
            // make tcpdump disappear from the descendants list. Never search by name/PID.
            List<ProcessHandle> descendants = new ArrayList<>(descendants(child));
            List<ProcessHandle> live = descendants.stream().filter(ProcessHandle::isAlive).toList();
            if (live.isEmpty()) {
                destroy(child.toHandle());
            } else {
                // Let wrappers/monitors reap their own children and keep inherited
                // stdout/stderr open while tcpdump flushes packets and final stats.
                Set<Long> parents = live.stream().flatMap(handle -> handle.parent().stream())
                        .map(ProcessHandle::pid).collect(java.util.stream.Collectors.toSet());
                live.stream().filter(handle -> !parents.contains(handle.pid())).forEach(MacCaptureAdapter::destroy);
            }
            waitFor(child, 1500);
            // Retain handles across escalation/reparenting, including children that
            // appeared after the initial snapshot. No process-name/PID searches.
            descendants(child).forEach(handle -> { if (!descendants.contains(handle)) descendants.add(handle); });
            descendants.stream().filter(ProcessHandle::isAlive).forEach(MacCaptureAdapter::destroyForcibly);
            waitFor(child, 750);
            if (child.isAlive()) destroy(child.toHandle());
            waitFor(child, 375);
            if (child.isAlive()) destroyForcibly(child.toHandle());
            waitFor(child, 375);
            // A killed descendant can take a moment to leave the process table.
            long deadline = System.nanoTime() + 250_000_000L;
            while (descendants.stream().anyMatch(ProcessHandle::isAlive) && System.nanoTime() < deadline) {
                try { Thread.sleep(10); }
                catch (InterruptedException exc) { Thread.currentThread().interrupt(); break; }
            }
            // Leave pipe closure to the capture reader after EOF. Closing here could
            // race the final bytes of a descendant still using the inherited pipe.
            if (!child.isAlive()) closeQuietly(child.getOutputStream());
            return !child.isAlive() && descendants.stream().noneMatch(ProcessHandle::isAlive);
        }
    }
    private static List<ProcessHandle> descendants(Process child) {
        try (var handles = child.descendants()) { return handles.toList(); }
        catch (RuntimeException ignored) {
            // Some restricted runtimes deny process enumeration. The directly owned
            // child must still be reaped and terminal events must still be delivered.
            return List.of();
        }
    }
    private static void destroy(ProcessHandle handle) {
        try { if (handle.isAlive()) handle.destroy(); } catch (SecurityException ignored) { }
    }
    private static void destroyForcibly(ProcessHandle handle) {
        try { if (handle.isAlive()) handle.destroyForcibly(); } catch (SecurityException ignored) { }
    }
    private static void waitFor(Process child, long milliseconds) {
        try { child.waitFor(milliseconds, TimeUnit.MILLISECONDS); }
        catch (InterruptedException exc) { Thread.currentThread().interrupt(); }
    }
    private static void closeQuietly(AutoCloseable closeable) {
        try { closeable.close(); } catch (Exception ignored) { }
    }
}
