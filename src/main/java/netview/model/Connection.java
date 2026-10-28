package netview.model;

public record Connection(long id, String label, String protocol, String src, String dst,
                         Integer sourcePort, Integer destinationPort, Long pid, String process,
                         Long effectivePid, String effectiveProcess, long packetCount,
                         long sentBytes, long receivedBytes) {}
