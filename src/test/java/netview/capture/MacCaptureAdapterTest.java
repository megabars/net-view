package netview.capture;

import netview.model.CapturedFrame;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static netview.capture.PcapngFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class MacCaptureAdapterTest {
    private List<CaptureEvent> awaitDone(MacCaptureAdapter adapter) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(7).toNanos();
        while (adapter.running() && System.nanoTime() < deadline) Thread.sleep(10);
        assertFalse(adapter.running(), "Capture worker failed to stop");
        List<CaptureEvent> events = new ArrayList<>();
        CaptureEvent event;
        while ((event = adapter.poll()) != null) events.add(event);
        return events;
    }
    private Process child(String mode) throws IOException {
        String executable = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        return new ProcessBuilder(executable, "-cp", System.getProperty("java.class.path"),
                CaptureChild.class.getName(), mode).start();
    }
    @Test void invalidSelectionRejected() {
        try (var adapter = new MacCaptureAdapter(command -> { throw new AssertionError("must not spawn"); }, true)) {
            for (Set<Long> pids : List.of(Set.<Long>of(), Set.of(-1L), Set.of(0L), Set.of(0x1_0000_0000L)))
                assertThrows(IllegalArgumentException.class, () -> adapter.start(pids));
            assertFalse(adapter.running());
        }
    }
    @Test void explicitPlatformErrorAndLaunchFailure() throws Exception {
        for (boolean supported : new boolean[]{false, true}) {
            try (var adapter = new MacCaptureAdapter(command -> { throw new IOException("capture unavailable"); }, supported)) {
                adapter.start(Set.of(123L));
                List<CaptureEvent> events = awaitDone(adapter);
                assertEquals(List.of("error", "stats", "stopped"), events.stream().map(CaptureEvent::type).toList());
                assertTrue(events.getFirst().message().contains(supported ? "unavailable" : "macOS"));
                assertNull(events.get(1).kernelDropped());
            }
        }
    }
    @Test void boundedQueueReservesControlsAndReportsDrops() {
        try (var adapter = new MacCaptureAdapter()) {
            CapturedFrame frame = new CapturedFrame(0, new byte[1024 * 1024], 1, 1024 * 1024,
                    null, "", null, "", "", "unknown");
            for (int i = 0; i < 100; i++) adapter.emit(new CaptureEvent("packet", frame, "", 0, null));
            for (int i = 0; i < 100; i++) adapter.stats();
            adapter.emit(CaptureEvent.control("stopped"));
            for (int i = 0; i < 32; i++) assertEquals("packet", adapter.poll().type());
            assertEquals(68, adapter.poll().dropped());
            assertEquals("stopped", adapter.poll().type());
            assertNull(adapter.poll());
            for (int i = 0; i < 2100; i++) adapter.emit(CaptureEvent.control("ready"));
            adapter.emit(new CaptureEvent("error", null, "must remain visible", 0, null));
            adapter.emit(CaptureEvent.control("stopped"));
            int count = 0; CaptureEvent last = null, previous = null;
            CaptureEvent current;
            while ((current = adapter.poll()) != null) { previous = last; last = current; count++; }
            assertEquals(2000, count); assertEquals("error", previous.type()); assertEquals("stopped", last.type());
        }
    }
    @Test void filtersActualPidAndEffectivePidAndReportsStreamEnd() throws Exception {
        ByteOrder le = ByteOrder.LITTLE_ENDIAN;
        byte[] data = join(attributed(le), packet(le)); // second packet has no ownership.
        for (long selected : new long[]{123, 456, 999}) {
            List<List<String>> commands = new ArrayList<>();
            try (var adapter = new MacCaptureAdapter(command -> {
                commands.add(command); return child(Base64.getEncoder().encodeToString(data));
            }, true)) {
                adapter.start(Set.of(selected));
                List<CaptureEvent> events = awaitDone(adapter);
                assertEquals(1, events.stream().filter(e -> e.type().equals("ready")).count());
                assertEquals(selected == 999 ? 0 : 1, events.stream().filter(e -> e.type().equals("packet")).count());
                assertTrue(events.stream().anyMatch(e -> e.type().equals("error") && e.message().contains("unexpectedly")));
                CaptureEvent stats = events.stream().filter(e -> e.type().equals("stats")).findFirst().orElseThrow();
                assertEquals(7L, stats.kernelDropped());
                assertEquals("stopped", events.getLast().type());
                List<String> command = commands.getFirst();
                assertEquals(List.of("/usr/bin/sudo", "-n", "/usr/sbin/tcpdump"), command.subList(0, 3));
                assertEquals("(pid=" + selected + " or epid=" + selected + ")", command.get(command.indexOf("-Q") + 1));
                assertEquals(System.getProperty("user.name"), command.get(command.indexOf("-Z") + 1));
                assertTrue(command.contains("-P")); assertEquals("ip or ip6", command.getLast());
            }
        }
    }
    @Test void sudoErrorIncludesTerminalGuidance() throws Exception {
        try (var adapter = new MacCaptureAdapter(command -> child("error"), true)) {
            adapter.start(Set.of(123L));
            List<CaptureEvent> events = awaitDone(adapter);
            String error = events.stream().filter(e -> e.type().equals("error")).findFirst().orElseThrow().message();
            assertTrue(error.contains("sudo -v")); assertTrue(error.contains("same Terminal"));
            assertEquals("stopped", events.getLast().type());
        }
    }
    @Test void stopInterruptsIdlePipeAndReapsChild() throws Exception {
        List<Process> children = new CopyOnWriteArrayList<>();
        try (var adapter = new MacCaptureAdapter(command -> {
            Process process = child("idle"); children.add(process); return process;
        }, true)) {
            adapter.start(Set.of(123L));
            long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
            while (children.isEmpty() && System.nanoTime() < deadline) Thread.sleep(10);
            assertFalse(children.isEmpty());
            assertThrows(IllegalStateException.class, () -> adapter.start(Set.of(123L)));
            long start = System.nanoTime();
            adapter.stop();
            assertTrue(System.nanoTime() - start < Duration.ofSeconds(1).toNanos());
            List<CaptureEvent> events = awaitDone(adapter);
            assertFalse(children.getFirst().isAlive());
            assertFalse(events.stream().anyMatch(e -> e.type().equals("error")));
            CaptureEvent stats = events.stream().filter(e -> e.type().equals("stats")).findFirst().orElseThrow();
            assertNull(stats.kernelDropped(), "Missing kernel statistics must remain unknown");
            assertEquals("stopped", events.getLast().type());
        }
    }
    @Test void stopPreservesDelayedFinalStatsFromWrappedChildAndReapsBoth() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeFalse(System.getProperty("os.name", "").startsWith("Windows"),
                "This regression exercises POSIX SIGTERM shutdown hooks");
        List<Process> wrappers = new CopyOnWriteArrayList<>();
        List<ProcessHandle> descendants = new ArrayList<>();
        try (var adapter = new MacCaptureAdapter(command -> {
            Process wrapper = child("wrapped-final-stats"); wrappers.add(wrapper); return wrapper;
        }, true)) {
            adapter.start(Set.of(123L));
            long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
            boolean ready = false;
            while (!ready && System.nanoTime() < deadline) {
                CaptureEvent event = adapter.poll();
                ready = event != null && event.type().equals("ready");
                if (!ready) Thread.sleep(10);
            }
            assertTrue(ready, "Wrapped capture never became ready");
            assertEquals(1, wrappers.size());
            try (var handles = wrappers.getFirst().descendants()) { descendants.addAll(handles.toList()); }
            assertEquals(1, descendants.size(), "Fixture must have a wrapper and one capture child");
            adapter.stop();
            List<CaptureEvent> events = awaitDone(adapter);
            assertFalse(wrappers.getFirst().isAlive(), "Wrapper must be reaped");
            assertTrue(descendants.stream().noneMatch(ProcessHandle::isAlive), "Capture child must not remain alive");
            CaptureEvent stats = events.stream().filter(e -> e.type().equals("stats")).findFirst().orElseThrow();
            assertEquals(0L, stats.kernelDropped(), "The child's delayed final kernel count must arrive before stopped");
            assertFalse(events.stream().anyMatch(e -> e.type().equals("error")), events.toString());
            assertEquals("stopped", events.getLast().type());
        } finally {
            descendants.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
            for (Process wrapper : wrappers) {
                if (wrapper.isAlive()) wrapper.destroyForcibly();
                wrapper.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
            }
        }
    }

    @Test void closeWaitsForChildAndAdapterCannotRestart() throws Exception {
        List<Process> children = new CopyOnWriteArrayList<>();
        var adapter = new MacCaptureAdapter(command -> {
            Process process = child("idle"); children.add(process); return process;
        }, true);
        adapter.start(Set.of(123L));
        long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
        while (children.isEmpty() && System.nanoTime() < deadline) Thread.sleep(10);
        adapter.close();
        assertFalse(adapter.running());
        assertTrue(children.stream().noneMatch(Process::isAlive));
        assertThrows(IllegalStateException.class, () -> adapter.start(Set.of(123L)));
    }
    @Test void catalogListsExecutableIdentity() {
        List<ProcessInfo> processes = ProcessCatalog.list();
        ProcessInfo current = processes.stream().filter(p -> p.pid() == ProcessHandle.current().pid()).findFirst().orElseThrow();
        assertFalse(current.name().isBlank());
        assertFalse(current.path().contains("CaptureChild"));
    }
}
