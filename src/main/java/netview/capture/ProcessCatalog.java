package netview.capture;

import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public final class ProcessCatalog {
    private ProcessCatalog() {}
    public static List<ProcessInfo> list() {
        try (var handles = ProcessHandle.allProcesses()) {
            return handles.map(handle -> {
                String command = handle.info().command().orElse("");
                String name = command.isEmpty() ? "PID " + handle.pid() : Path.of(command).getFileName().toString();
                return new ProcessInfo(handle.pid(), name, command);
            }).sorted(Comparator.comparing((ProcessInfo p) -> p.name().toLowerCase(Locale.ROOT))
                    .thenComparingLong(ProcessInfo::pid)).toList();
        }
    }
}
