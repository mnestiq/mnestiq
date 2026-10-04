"""mnestiq: tamper-evident flight recorder for AI agents."""

from .recorder import Recorder, RecorderError, Run, Segment, current_run
from .sinks import FileSink, HeadFile, MemorySink, SinkError
from .verify import Report, verify_file, verify_lines

__version__ = "0.1.0"
SPEC_VERSION = "0.1"

__all__ = [
    "FileSink",
    "HeadFile",
    "MemorySink",
    "Recorder",
    "RecorderError",
    "Report",
    "Run",
    "Segment",
    "SinkError",
    "current_run",
    "verify_file",
    "verify_lines",
]
