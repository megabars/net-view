package netview.model;

import java.util.List;

public record DecodedPacket(CapturedFrame frame, String src, String dst, Integer sourcePort,
                            Integer destinationPort, String protocol, String summary, byte[] payload,
                            Long tcpSequence, int tcpFlags, List<String> issues, long wireLength) {
    public DecodedPacket { payload = payload.clone(); issues = List.copyOf(issues); }
    @Override public byte[] payload() { return payload.clone(); }
    public int payloadLength() { return payload.length; }
}
