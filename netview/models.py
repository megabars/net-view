"""OS-independent capture boundary shared by all adapters."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CapturedFrame:
    timestamp: float
    data: bytes
    linktype: int
    original_length: int = 0
    pid: int | None = None
    process: str = ""
    effective_pid: int | None = None
    effective_process: str = ""
    interface: str = ""
    direction: str = "unknown"
