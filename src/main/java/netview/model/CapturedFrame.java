package netview.model;

import java.util.Arrays;
import java.util.Objects;

/** OS-independent immutable frame; timestamp is Unix seconds, exactly as v1 JSON. */
public record CapturedFrame(double timestamp, byte[] data, long linktype, long originalLength,
                            Long pid, String process, Long effectivePid, String effectiveProcess,
                            String networkInterface, String direction) {
    public CapturedFrame {
        if (!Double.isFinite(timestamp) || data == null || linktype < 0 || linktype > 0xffff_ffffL || originalLength < 0
                || originalLength > 0xffff_ffffL) throw new IllegalArgumentException("Invalid frame metadata");
        if ((pid != null && (pid < 0 || pid > Integer.MAX_VALUE))
                || (effectivePid != null && (effectivePid < 0 || effectivePid > Integer.MAX_VALUE)))
            throw new IllegalArgumentException("Invalid PID");
        checkText(process, 256); checkText(effectiveProcess, 256);
        checkText(networkInterface, 128); checkText(direction, 32);
        data = data.clone();
    }
    private static void checkText(String text, int max) {
        if (text == null || text.codePointCount(0, text.length()) > max)
            throw new IllegalArgumentException("Invalid metadata text");
    }
    @Override public byte[] data() { return data.clone(); }
    public int capturedLength() { return data.length; }
    @Override public boolean equals(Object other) {
        return other instanceof CapturedFrame f && Double.compare(timestamp, f.timestamp) == 0
                && Arrays.equals(data, f.data) && linktype == f.linktype && originalLength == f.originalLength
                && Objects.equals(pid, f.pid) && process.equals(f.process)
                && Objects.equals(effectivePid, f.effectivePid) && effectiveProcess.equals(f.effectiveProcess)
                && networkInterface.equals(f.networkInterface) && direction.equals(f.direction);
    }
    @Override public int hashCode() {
        return 31 * Objects.hash(timestamp, linktype, originalLength, pid, process, effectivePid,
                effectiveProcess, networkInterface, direction) + Arrays.hashCode(data);
    }
}
