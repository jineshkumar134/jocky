"""Platform abstraction for JOCKY.

Provides dataclasses representing platform information and security status, and an abstract
base class that concrete adapters must implement.
"""

import abc
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PlatformInfo:
    """Immutable container for basic platform details.

    Attributes
    ----------
    os_name: str
        Human readable operating system name (e.g., "Windows", "Linux").
    os_version: str
        OS version string.
    architecture: str
        CPU architecture (e.g., "x86_64", "AMD64").
    hostname: str
        System hostname.
    runtime: str
        Python runtime identifier (e.g., "Python 3.11.6").
    adapter_name: str
        Name of the adapter class that produced this info.
    """

    os_name: str
    os_version: str
    architecture: str
    hostname: str
    runtime: str
    adapter_name: str


@dataclass(frozen=True)
class FeatureStatus:
    """Status of a security feature.

    The fields follow the semantics required by the specification:
    - ``applicable`` – whether the feature is relevant on this platform.
    - ``available`` – whether the platform can query the feature (None if unknown).
    - ``enabled`` – whether the feature is enabled (None if unknown).
    - ``source`` – optional string indicating where the information was obtained.
    """

    applicable: bool
    available: Optional[bool] = None
    enabled: Optional[bool] = None
    source: Optional[str] = None


@dataclass(frozen=True)
class SecurityStatus:
    """Aggregate security feature statuses.

    Attributes
    ----------
    hvci: FeatureStatus
    vbs: FeatureStatus
    secure_boot: FeatureStatus
    """

    hvci: FeatureStatus
    vbs: FeatureStatus
    secure_boot: FeatureStatus


class BasePlatformAdapter(abc.ABC):
    """Abstract base class for platform adapters.

    Concrete adapters must implement ``get_platform_info`` and ``get_security_status``.
    """

    @abc.abstractmethod
    def get_platform_info(self) -> PlatformInfo:
        """Return basic platform information."""

    @abc.abstractmethod
    def get_security_status(self) -> SecurityStatus:
        """Return security feature detection results."""

