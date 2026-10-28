package netview.protocol;

import netview.model.CapturedFrame;
import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import static netview.protocol.PacketFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class PacketDecoderTest {
    @Test void tcpHttpAndMetadata() {
        var frame = tcp("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", 100, 24, false, 55L);
        var p = PacketDecoder.decode(frame);
        assertEquals("TCP", p.protocol()); assertEquals("127.0.0.1", p.src()); assertEquals("127.0.0.2", p.dst());
        assertEquals(10000, p.sourcePort()); assertEquals(80, p.destinationPort()); assertEquals(100L, p.tcpSequence());
        assertTrue(p.summary().contains("HTTP GET / HTTP/1.1")); assertEquals(frame, p.frame()); assertTrue(p.issues().isEmpty());
    }
    @Test void everyTruncationKeepsOriginalAndReportsIssue() {
        byte[] network = tcp("hello", 100, 24, false, 55L).data();
        byte[] ethernet = ByteBuffer.allocate(14 + network.length).put(new byte[12]).putShort((short) 0x0800).put(network).array();
        for (int length = 0; length < ethernet.length; length++) {
            var f = new CapturedFrame(0, Arrays.copyOf(ethernet, length), 1, ethernet.length, null, "", null, "", "", "");
            var p = PacketDecoder.decode(f); assertFalse(p.issues().isEmpty(), "length " + length); assertArrayEquals(f.data(), p.frame().data());
        }
    }
    @Test void supportedEncodingsAndVlanPadding() {
        byte[] network = tcp("hello", 100, 24, false, 55L).data();
        for (int type : new int[]{12, 101, 228}) assertEquals("hello", new String(PacketDecoder.decode(raw(network, type, 55L, false)).payload(), StandardCharsets.UTF_8));
        for (int type : new int[]{0, 108}) {
            byte[] loop = ByteBuffer.allocate(network.length + 4).putInt(type == 0 ? 0x02000000 : 2).put(network).array();
            assertEquals(5, PacketDecoder.decode(raw(loop, type, 55L, false)).payloadLength());
        }
        byte[] ether = ByteBuffer.allocate(18 + network.length + 7).put(new byte[12]).putShort((short) 0x8100).putShort((short) 1).putShort((short) 0x0800).put(network).put("padding".getBytes(StandardCharsets.US_ASCII)).array();
        assertEquals(5, PacketDecoder.decode(raw(ether, 1, 55L, false)).payloadLength());
    }
    @Test void ipv6ExtensionsAndFragments() {
        byte[] udp = ByteBuffer.allocate(10).putShort((short) 10000).putShort((short) 53).putShort((short) 10).putShort((short) 0).put(new byte[]{0, -1}).array();
        byte[] addresses = new byte[32]; addresses[15] = 1; addresses[16] = 0x20; addresses[17] = 1; addresses[18] = 0x0d; addresses[19] = (byte) 0xb8; addresses[31] = 1;
        byte[] ip = ByteBuffer.allocate(48 + udp.length).putInt(6 << 28).putShort((short) (udp.length + 8)).put((byte) 0).put((byte) 64).put(addresses).put((byte) 17).put(new byte[7]).put(udp).array();
        var p = PacketDecoder.decode(raw(ip, 229, null, false));
        assertEquals("::1", p.src()); assertEquals("2001:db8::1", p.dst()); assertEquals("UDP", p.protocol()); assertArrayEquals(new byte[]{0, -1}, p.payload());
        ip[6] = 44; p = PacketDecoder.decode(raw(ip, 229, null, false)); assertNull(p.sourcePort()); assertTrue(p.summary().contains("fragment"));
        byte[] tcp = tcp("data", 1, 24, false, null).data(); tcp[6] = 0x20;
        p = PacketDecoder.decode(raw(tcp, 228, null, false)); assertNull(p.sourcePort()); assertTrue(p.summary().contains("fragment"));
    }
    @Test void tlsAndUnknownKeepBytes() {
        byte[] tls = {23, 3, 3, 0, 3, 1, 2, 3};
        var p = PacketDecoder.decode(frame(tls, 100, 24, false, null, false));
        assertTrue(p.summary().contains("encrypted")); assertArrayEquals(tls, p.payload());
        byte[] unknown = {1, 2, 3}; p = PacketDecoder.decode(raw(unknown, 9999, null, false));
        assertEquals("Unknown", p.protocol()); assertArrayEquals(unknown, p.payload());
    }
}
