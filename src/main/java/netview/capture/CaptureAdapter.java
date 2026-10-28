package netview.capture;

import java.util.Set;

public interface CaptureAdapter extends AutoCloseable {
    void start(Set<Long> pids);
    void stop();
    boolean running();
    /** Nonblocking; returns null when no event is currently available. */
    CaptureEvent poll();
    @Override void close();
}
