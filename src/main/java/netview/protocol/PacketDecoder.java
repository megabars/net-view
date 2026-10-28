package netview.protocol;

import netview.model.CapturedFrame;
import netview.model.DecodedPacket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Conservative decoding: unavailable transport fields remain unknown, original frames are retained. */
public final class PacketDecoder {
    private PacketDecoder() {}
    public static DecodedPacket decode(CapturedFrame frame) { return new Decoder(frame).decode(); }

    private static final class Decoder {
        final CapturedFrame frame;
        final byte[] raw;
        final List<String> issues = new ArrayList<>();
        String src = "", dst = "", protocol = "Unknown", summary = "Unknown frame";
        Integer sport, dport;
        Long sequence;
        int flags;
        byte[] payload = new byte[0];
        Decoder(CapturedFrame frame) { this.frame = frame; raw = frame.data(); }
        DecodedPacket done() {
            return new DecodedPacket(frame, src, dst, sport, dport, protocol, summary,
                    payload, sequence, flags, issues, frame.originalLength() == 0 ? raw.length : frame.originalLength());
        }
        DecodedPacket fail(String issue) { issues.add(issue); return done(); }
        DecodedPacket decode() {
            if (frame.originalLength() > raw.length) issues.add("Capture truncated: fewer bytes than the original frame");
            int offset = 0, ether = -1;
            if (frame.linktype() > Integer.MAX_VALUE) {
                payload = raw; return fail("Unsupported link type " + frame.linktype());
            }
            switch ((int) frame.linktype()) {
                case 1 -> {
                    if (raw.length < 14) return fail("Truncated Ethernet header");
                    offset = 14; ether = u16(raw, 12);
                    for (int i = 0; i < 4 && vlan(ether); i++) {
                        if (raw.length < offset + 4) return fail("Truncated VLAN header");
                        ether = u16(raw, offset + 2); offset += 4;
                    }
                    if (vlan(ether)) return fail("VLAN nesting limit exceeded");
                    if (ether == 0x0806) {
                        protocol = summary = "ARP"; payload = slice(raw, offset, raw.length); return done();
                    }
                }
                case 0, 108 -> {
                    if (raw.length < 4) return fail("Truncated loopback header");
                    long family = u32(raw, 0), alternate = frame.linktype() == 0 ? Integer.toUnsignedLong(Integer.reverseBytes((int) family)) : family;
                    offset = 4;
                    if (family == 2 || alternate == 2) ether = 0x0800;
                    else if (ipv6Family(family) || ipv6Family(alternate)) ether = 0x86dd;
                    else return fail("Unsupported loopback address family");
                }
                case 12, 101 -> { if (raw.length > 0) ether = switch (u8(raw, 0) >> 4) { case 4 -> 0x0800; case 6 -> 0x86dd; default -> -1; }; }
                case 228 -> ether = 0x0800;
                case 229 -> ether = 0x86dd;
                case 113, 276 -> {
                    offset = frame.linktype() == 113 ? 16 : 20;
                    if (raw.length < offset) return fail("Truncated cooked capture header");
                    ether = u16(raw, frame.linktype() == 113 ? 14 : 0);
                }
                default -> { payload = raw; return fail("Unsupported link type " + frame.linktype()); }
            }
            if (ether != 0x0800 && ether != 0x86dd) {
                payload = slice(raw, offset, raw.length); summary = "Unsupported network protocol";
                return fail("Unsupported network protocol");
            }
            byte[] network = slice(raw, offset, raw.length), transport;
            int next;
            if (ether == 0x0800) {
                protocol = summary = "IPv4";
                if (network.length < 20) return fail("Truncated IPv4 header");
                int ihl = (u8(network, 0) & 15) * 4, total = u16(network, 2);
                if (u8(network, 0) >> 4 != 4 || ihl < 20 || total < ihl) return fail("Malformed IPv4 header or length");
                src = ipv4(network, 12); dst = ipv4(network, 16);
                if (network.length < ihl) return fail("Truncated IPv4 options");
                if (network.length < total) issues.add("Truncated IPv4 packet");
                transport = slice(network, ihl, Math.min(network.length, total)); next = u8(network, 9);
                if ((u16(network, 6) & 0x3fff) != 0) {
                    payload = transport; summary = "IPv4 fragment (unsupported)";
                    return fail("IPv4 fragments are not reassembled; transport decoding skipped");
                }
            } else {
                protocol = summary = "IPv6";
                if (network.length < 40) return fail("Truncated IPv6 header");
                if (u8(network, 0) >> 4 != 6) return fail("Malformed IPv6 version");
                src = ipv6(network, 8); dst = ipv6(network, 24);
                int length = u16(network, 4); next = u8(network, 6);
                if (length == 0 && network.length > 40) return fail("IPv6 jumbograms are unsupported");
                if (network.length < 40 + length) issues.add("Truncated IPv6 packet");
                network = slice(network, 0, Math.min(network.length, 40 + length));
                int cursor = 40, count = 0;
                while (extension(next)) {
                    if (count++ == 16) return fail("IPv6 extension traversal limit exceeded");
                    if (next == 44) {
                        payload = slice(network, cursor, network.length); summary = "IPv6 fragment (unsupported)";
                        return fail("IPv6 fragments are not reassembled; transport decoding skipped");
                    }
                    if (cursor + 2 > network.length) return fail("Truncated IPv6 extension header");
                    int size = next == 51 ? (u8(network, cursor + 1) + 2) * 4 : (u8(network, cursor + 1) + 1) * 8;
                    if (cursor + size > network.length) return fail("Truncated IPv6 extension body");
                    next = u8(network, cursor); cursor += size;
                    // Match the reference's strict traversal bound, including a terminal 16th extension.
                    if (count == 16) return fail("IPv6 extension traversal limit exceeded");
                }
                transport = slice(network, cursor, network.length);
            }
            payload = transport;
            if (next == 6) {
                protocol = summary = "TCP";
                if (transport.length < 20) { payload = new byte[0]; return fail("Truncated TCP header"); }
                sport = u16(transport, 0); dport = u16(transport, 2); sequence = u32(transport, 4); flags = u8(transport, 13);
                int size = (u8(transport, 12) >> 4) * 4;
                if (size < 20) { payload = new byte[0]; return fail("Malformed TCP data offset"); }
                if (transport.length < size) { payload = new byte[0]; return fail("Truncated TCP options"); }
                payload = slice(transport, size, transport.length);
                List<String> names = new ArrayList<>();
                int[] bits = {2, 16, 1, 4, 8}; String[] labels = {"SYN", "ACK", "FIN", "RST", "PSH"};
                for (int i = 0; i < bits.length; i++) if ((flags & bits[i]) != 0) names.add(labels[i]);
                summary = "TCP " + sport + " → " + dport + " " + String.join(" ", names) + "; " + payload.length + " payload bytes";
                describeApplication();
            } else if (next == 17) {
                protocol = summary = "UDP";
                if (transport.length < 8) { payload = new byte[0]; return fail("Truncated UDP header"); }
                sport = u16(transport, 0); dport = u16(transport, 2); int size = u16(transport, 4);
                if (size < 8) { payload = new byte[0]; return fail("Malformed or unsupported UDP length"); }
                if (transport.length < size) issues.add("Truncated UDP datagram");
                payload = slice(transport, 8, Math.min(transport.length, size));
                summary = "UDP " + sport + " → " + dport + "; " + payload.length + " payload bytes";
            } else if (next == 1 || next == 58) protocol = summary = next == 58 ? "ICMPv6" : "ICMP";
            else if (next == 50) { protocol = "ESP"; summary = "ESP (encrypted payload)"; }
            else if (next == 59) { summary = "IPv6 no next header"; payload = new byte[0]; }
            else summary = protocol + " protocol " + next + " (unsupported)";
            return done();
        }
        void describeApplication() {
            if (payload.length >= 5 && u8(payload, 0) >= 20 && u8(payload, 0) <= 23 && payload[1] == 3 && u8(payload, 2) <= 4) {
                summary += "; TLS record (encrypted content is not decrypted)";
            } else {
                String prefix = new String(payload, 0, Math.min(payload.length, 8), StandardCharsets.US_ASCII);
                if (List.of("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/1.").stream().noneMatch(prefix::startsWith)) return;
                int end = 0;
                while (end < Math.min(payload.length, 200) && !(payload[end] == 13 && end + 1 < payload.length && payload[end + 1] == 10)) end++;
                summary += "; HTTP " + new String(payload, 0, end, StandardCharsets.US_ASCII);
            }
        }
    }
    private static boolean vlan(int n) { return n == 0x8100 || n == 0x88a8 || n == 0x9100; }
    private static boolean ipv6Family(long n) { return n == 10 || n == 24 || n == 28 || n == 30; }
    private static boolean extension(int n) { return n == 0 || n == 43 || n == 44 || n == 51 || n == 60; }
    private static int u8(byte[] b, int p) { return b[p] & 255; }
    private static int u16(byte[] b, int p) { return u8(b, p) << 8 | u8(b, p + 1); }
    private static long u32(byte[] b, int p) { return ((long) u16(b, p) << 16) | u16(b, p + 2); }
    private static byte[] slice(byte[] b, int from, int to) { return Arrays.copyOfRange(b, from, to); }
    private static String ipv4(byte[] b, int p) { return u8(b,p) + "." + u8(b,p+1) + "." + u8(b,p+2) + "." + u8(b,p+3); }
    private static String ipv6(byte[] b, int p) {
        int[] words = new int[8]; int best = -1, size = 1;
        for (int i = 0; i < 8; i++) words[i] = u16(b, p + i * 2);
        for (int i = 0; i < 8;) {
            if (words[i] != 0) { i++; continue; }
            int start = i; while (i < 8 && words[i] == 0) i++;
            if (i - start > size) { best = start; size = i - start; }
        }
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < 8;) {
            if (i == best) { text.append("::"); i += size; }
            else { if (!text.isEmpty() && text.charAt(text.length()-1) != ':') text.append(':'); text.append(Integer.toHexString(words[i++])); }
        }
        return text.toString();
    }
}
