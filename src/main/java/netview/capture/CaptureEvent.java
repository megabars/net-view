package netview.capture;

import netview.model.CapturedFrame;

/** Types: ready, packet, error, stats, stopped. Kernel drops remain null until reported. */
public record CaptureEvent(String type, CapturedFrame frame, String message,
                           long dropped, Long kernelDropped) {
    static CaptureEvent control(String type) { return new CaptureEvent(type, null, "", 0, null); }
}
