package netview.capture;

/** Executable identity only; command-line arguments are deliberately excluded. */
public record ProcessInfo(long pid, String name, String path) {}
