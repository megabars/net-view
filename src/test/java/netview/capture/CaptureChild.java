package netview.capture;

import java.util.Base64;
import java.nio.file.Path;
import java.nio.ByteOrder;

/** A Java-only child process fixture: no elevated privileges or packet devices. */
public final class CaptureChild {
    public static void main(String[] args) throws Exception {
        if (args[0].equals("wrapped-final-stats")) {
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            Process child = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    CaptureChild.class.getName(), "delayed-final-stats").inheritIO().start();
            child.waitFor();
            return;
        }
        if (args[0].equals("delayed-final-stats")) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try { Thread.sleep(250); } catch (InterruptedException ignored) { }
                // Native tcpdump can flush buffered packets before its final stderr
                // statistics. Treat a broken output pipe like its default SIGPIPE.
                byte[] packet = PcapngFixtures.packet(ByteOrder.LITTLE_ENDIAN,
                        new byte[512 * 1024], 512 * 1024, 0, 0);
                System.out.writeBytes(PcapngFixtures.join(
                        PcapngFixtures.iface(ByteOrder.LITTLE_ENDIAN, "lo0", 0), packet, packet));
                System.out.flush();
                if (System.out.checkError()) return;
                System.err.println("0 packets dropped by kernel");
                System.err.flush();
            }));
            System.err.println("tcpdump: listening on pktap,all");
            System.out.write(PcapngFixtures.section(ByteOrder.LITTLE_ENDIAN));
            System.out.flush();
            Thread.sleep(30_000);
            return;
        }
        if (args[0].equals("idle")) { Thread.sleep(30_000); return; }
        if (args[0].equals("error")) {
            System.err.println("sudo: a password is required");
            System.exit(1);
        }
        System.err.println("tcpdump: listening on pktap,all");
        System.out.write(Base64.getDecoder().decode(args[0]));
        System.out.flush();
        System.err.println("7 packets dropped by kernel");
    }
}
