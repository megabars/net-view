package netview.model;

import java.util.List;

public record StreamPart(String name, byte[] data, List<String> issues) {
    public StreamPart { data = data.clone(); issues = List.copyOf(issues); }
    @Override public byte[] data() { return data.clone(); }
    public int length() { return data.length; }
}
