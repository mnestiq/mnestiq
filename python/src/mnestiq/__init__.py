"""mnestiq: tamper-evident flight recorder for AI agents."""

from .recorder import Recorder, RecorderError, Run, Segment, current_run
from .signers import AzureKeyVaultSigner, LocalSigner, Signer, SignerClient, SignerError
from .sinks import FileSink, HeadFile, MemorySink, SinkError
from .timestamps import Timestamper, TimestampError
from .verify import Report, verify_file, verify_lines

__version__ = "0.3.0"
SPEC_VERSION = "0.2"

__all__ = [
    "AzureKeyVaultSigner",
    "FileSink",
    "HeadFile",
    "LocalSigner",
    "MemorySink",
    "Recorder",
    "RecorderError",
    "Report",
    "Run",
    "Segment",
    "Signer",
    "SignerClient",
    "SignerError",
    "SinkError",
    "TimestampError",
    "Timestamper",
    "current_run",
    "verify_file",
    "verify_lines",
]
