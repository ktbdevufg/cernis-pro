"""Use-Cases der Aussenkontakte-Aufzeichnung und ihre Application-Exceptions (E3a)."""

from application.outbound_log.errors import (
    RecordingConflict,
    RecordingNotFound,
)
from application.outbound_log.recorder import (
    ContactSnapshotProvider,
    RunOutboundRecorder,
)
from application.outbound_log.use_cases import (
    CreateOutboundRecording,
    DeleteOutboundRecording,
    EnforceOutboundDetailRetention,
    GetOutboundAggregate,
    GetOutboundDetailRange,
    GetOutboundRecording,
    ListOutboundRecordings,
    PauseOutboundRecording,
    ResumeOutboundRecording,
    StartOutboundRecording,
    StopOutboundRecording,
)

__all__ = [
    "ContactSnapshotProvider",
    "CreateOutboundRecording",
    "DeleteOutboundRecording",
    "EnforceOutboundDetailRetention",
    "GetOutboundAggregate",
    "GetOutboundDetailRange",
    "GetOutboundRecording",
    "ListOutboundRecordings",
    "PauseOutboundRecording",
    "RecordingConflict",
    "RecordingNotFound",
    "ResumeOutboundRecording",
    "RunOutboundRecorder",
    "StartOutboundRecording",
    "StopOutboundRecording",
]
