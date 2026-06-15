"""Use-Cases der fritz_detail-Domaene und ihre Application-Exceptions."""

from application.fritz_detail.errors import FritzDetailApplicationError, FritzDetailAuthError
from application.fritz_detail.use_cases import GetFritzDetail

__all__ = [
    "FritzDetailApplicationError",
    "FritzDetailAuthError",
    "GetFritzDetail",
]
