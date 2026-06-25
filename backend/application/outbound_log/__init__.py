"""Use-Cases der Aussenkontakte-Aufzeichnung und ihre Application-Exceptions (E3a)."""

from application.outbound_log.errors import (
    RecordingConflict,
    RecordingNotFound,
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
    "StartOutboundRecording",
    "StopOutboundRecording",
]
