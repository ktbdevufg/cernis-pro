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
    EditOutboundRecording,
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

# Re-Export der Domaenen-Exceptions, damit der api-Rand sie fangen kann, OHNE
# ``domain`` direkt zu importieren (import-linter: api -> nur application). Die
# Use-Cases reichen ``InvalidRecordingTransition`` (falscher Zustandsuebergang) und
# ``RecordingConfigLocked`` (Konfig-Aenderung ausserhalb CREATED) aus der Domaene
# unveraendert durch; der Router mappt beide auf 409 -- darum braucht er die Namen aus
# dieser Schicht (Muster ``InvalidTaskTransition`` der monitoring-Schicht).
from domain.outbound_log import InvalidRecordingTransition, RecordingConfigLocked

__all__ = [
    "ContactSnapshotProvider",
    "CreateOutboundRecording",
    "DeleteOutboundRecording",
    "EditOutboundRecording",
    "EnforceOutboundDetailRetention",
    "GetOutboundAggregate",
    "GetOutboundDetailRange",
    "GetOutboundRecording",
    "InvalidRecordingTransition",
    "ListOutboundRecordings",
    "PauseOutboundRecording",
    "RecordingConfigLocked",
    "RecordingConflict",
    "RecordingNotFound",
    "ResumeOutboundRecording",
    "RunOutboundRecorder",
    "StartOutboundRecording",
    "StopOutboundRecording",
]
