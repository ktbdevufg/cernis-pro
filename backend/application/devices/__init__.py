"""Use-Cases der devices-Domaene und ihre Application-Exceptions."""

from application.devices.errors import (
    DeviceAlreadyExistsError,
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
    "DeviceNotFoundError",
    "DevicesApplicationError",
    "DismissDeviceFromWatch",
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
