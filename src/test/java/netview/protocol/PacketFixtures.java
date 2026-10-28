package netview.protocol;

import netview.model.CapturedFrame;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public final class PacketFixtures {
    private PacketFixtures() {}
    public static CapturedFrame tcp(String payload, long sequence, int flags, boolean reverse, Long pid) {
        return frame(payload.getBytes(StandardCharsets.UTF_8), sequence, flags, reverse, pid, false);
    }
    public static CapturedFrame frame(byte[] payload, long sequence, int flags, boolean reverse, Long pid, boolean udp) {
        ByteBuffer transport = ByteBuffer.allocate((udp ? 8 : 20) + payload.length).order(ByteOrder.BIG_ENDIAN);
        transport.putShort((short) (reverse ? 80 : 10000)).putShort((short) (reverse ? 10000 : 80));
        if (udp) transport.putShort((short) (payload.length + 8)).putShort((short) 0);
        else transport.putInt((int) sequence).putInt(0).put((byte) 0x50).put((byte) flags).putShort((short) 65535).putInt(0);
        transport.put(payload);
        return raw(ipv4(transport.array(), udp ? 17 : 6, reverse, 0), 228, pid, reverse);
    }
    public static byte[] ipv4(byte[] transport, int protocol, boolean reverse, int fragment) {
        return ByteBuffer.allocate(20 + transport.length).order(ByteOrder.BIG_ENDIAN).put((byte) 0x45).put((byte) 0)
                .putShort((short) (20 + transport.length)).putShort((short) 1).putShort((short) fragment).put((byte) 64).put((byte) protocol).putShort((short) 0)
                .putInt(reverse ? 0x7f000002 : 0x7f000001).putInt(reverse ? 0x7f000001 : 0x7f000002).put(transport).array();
    }
    public static CapturedFrame raw(byte[] raw, int type, Long pid, boolean reverse) {
        return new CapturedFrame(1234.5, raw, type, raw.length, pid, "test", 66L, "effective", "lo0", reverse ? "in" : "out");
    }
}
