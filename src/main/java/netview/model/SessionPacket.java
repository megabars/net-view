package netview.model;

public record SessionPacket(long id, long connectionId, DecodedPacket decoded) {}
