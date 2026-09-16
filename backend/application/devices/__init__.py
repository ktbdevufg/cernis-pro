"""Use-Cases der devices-Domaene und ihre Application-Exceptions."""

from application.devices.errors import (
    DeviceAlreadyExistsError,
    DeviceBroadcastMacError,
    DeviceNotFoundError,
    DevicesApplicationError,
    InvalidTrustStateError,
)
from application.devices.use_cases import (
    AnswerArchivePrompt,
    ArchiveDevice,
    CreateDevice,
    DeleteDevice,
    DismissDeviceFromWatch,
    GetArchiveCandidates,
    GetArchivedDevices,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    GetUnclassifiedDevices,
    RecordScannedHost,
    RestoreDevice,
    UpdateDeviceMeta,
)

__all__ = [
    "AnswerArchivePrompt",
    "ArchiveDevice",
    "CreateDevice",
    "DeleteDevice",
    "DeviceAlreadyExistsError",
    "DeviceBroadcastMacError",
    "DeviceNotFoundError",
    "DevicesApplicationError",
    "DismissDeviceFromWatch",
    "GetArchiveCandidates",
    "GetArchivedDevices",
    "GetDevice",
    "GetDeviceStats",
    "GetDevices",
    "GetUnclassifiedDevices",
    "InvalidTrustStateError",
    "RecordScannedHost",
    "RestoreDevice",
    "UpdateDeviceMeta",
]
