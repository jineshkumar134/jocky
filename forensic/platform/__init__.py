"""forensic.platform package – platform information and security feature detection."""

from .base import (
    BasePlatformAdapter,
    FeatureStatus,
    PlatformInfo,
    SecurityStatus,
)
from .factory import PlatformAdapterFactory
from .fixture import FixturePlatformAdapter
from .generic import GenericPlatformAdapter
from .linux import LinuxPlatformAdapter
from .windows import WindowsPlatformAdapter

__all__ = [
    "BasePlatformAdapter",
    "FeatureStatus",
    "PlatformInfo",
    "SecurityStatus",
    "PlatformAdapterFactory",
    "FixturePlatformAdapter",
    "GenericPlatformAdapter",
    "LinuxPlatformAdapter",
    "WindowsPlatformAdapter",
]
