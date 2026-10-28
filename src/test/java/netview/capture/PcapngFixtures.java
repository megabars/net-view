package netview.capture;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

final class PcapngFixtures {
    static byte[] join(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] array : arrays) out.writeBytes(array);
        return out.toByteArray();
    }
    static byte[] numbers(ByteOrder order, int... values) {
        ByteBuffer bytes = ByteBuffer.allocate(4 * values.length).order(order);
        for (int value : values) bytes.putInt(value);
        return bytes.array();
    }
    static byte[] option(ByteOrder order, int code, byte[] value) {
        return ByteBuffer.allocate(4 + ((value.length + 3) & ~3)).order(order)
                .putShort((short) code).putShort((short) value.length).put(value).array();
    }
    static byte[] block(ByteOrder order, int type, byte[] body) {
        int length = body.length + 12;
        return join(numbers(order, type, length), body, numbers(order, length));
    }
    static byte[] section(ByteOrder order) {
        return block(order, 0x0a0d0d0a, ByteBuffer.allocate(16).order(order)
                .putInt(0x1a2b3c4d).putShort((short) 1).putShort((short) 0).putLong(-1).array());
    }
    static byte[] iface(ByteOrder order, String name, int linktype, byte[]... extra) {
        return iface(order, name.getBytes(StandardCharsets.UTF_8), linktype, extra);
    }
    static byte[] iface(ByteOrder order, byte[] name, int linktype, byte[]... extra) {
        return block(order, 1, join(ByteBuffer.allocate(8).order(order).putShort((short) linktype)
                .putShort((short) 0).putInt(262144).array(), option(order, 2, name), join(extra)));
    }
    static byte[] process(ByteOrder order, long pid, String name) {
        return block(order, 0x80000001, join(numbers(order, (int) pid),
                option(order, 2, name.getBytes(StandardCharsets.UTF_8))));
    }
    static byte[] packet(ByteOrder order, byte[] data, int original, long ticks, int interfaceId, byte[]... options) {
        return block(order, 6, join(numbers(order, interfaceId, (int) (ticks >>> 32), (int) ticks, data.length, original),
                data, new byte[(-data.length) & 3], join(options)));
    }
    static byte[] packet(ByteOrder order, byte[]... options) {
        return packet(order, "hello".getBytes(StandardCharsets.UTF_8), 100, 1_500_000, 0, options);
    }
    static byte[] attributed(ByteOrder order) {
        return join(section(order), iface(order, "lo0", 0), process(order, 123, "client"),
                process(order, 456, "helper"), packet(order,
                        option(order, 2, numbers(order, 2)), option(order, 0x8001, numbers(order, 0)),
                        option(order, 0x8003, numbers(order, 1))));
    }
}
