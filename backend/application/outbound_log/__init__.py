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

# Re-Export der Domaenen-Exception, damit der api-Rand sie fangen kann, OHNE
# ``domain`` direkt zu importieren (import-linter: api -> nur application). Die
# Lifecycle-Use-Cases reichen ``InvalidRecordingTransition`` aus der Domaene
# unveraendert durch; der Router mappt sie auf 409 -- darum braucht er den Namen aus
# dieser Schicht (Muster ``InvalidTaskTransition`` der monitoring-Schicht).
from domain.outbound_log import InvalidRecordingTransition

__all__ = [
    "ContactSnapshotProvider",
    "CreateOutboundRecording",
    "DeleteOutboundRecording",
    "EnforceOutboundDetailRetention",
    "GetOutboundAggregate",
    "GetOutboundDetailRange",
    "GetOutboundRecording",
    "InvalidRecordingTransition",
    "ListOutboundRecordings",
    "PauseOutboundRecording",
    "RecordingConflict",
    "RecordingNotFound",
    "ResumeOutboundRecording",
    "RunOutboundRecorder",
    "StartOutboundRecording",
    "StopOutboundRecording",
]
