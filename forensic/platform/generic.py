"""Generic fallback platform adapter.

Provides basic platform detection using standard Python platform APIs.
Security features are marked NOT APPLICABLE where unsupported, never fabricated.
"""

from __future__ import annotations

import platform
import socket
import sys

from .base import BasePlatformAdapter, FeatureStatus, PlatformInfo, SecurityStatus


class GenericPlatformAdapter(BasePlatformAdapter):
    """Concrete generic adapter for POSIX / other operating systems (e.g. Darwin, BSD).

    All operations are read-only.
    """

    def get_platform_info(self) -> PlatformInfo:
        uname = platform.uname()
        runtime = f"Python {sys.version.split()[0]}"
        return PlatformInfo(
            os_name=uname.system or "GenericOS",
            os_version=uname.version or uname.release or "Unknown",
            architecture=uname.machine or "unknown",
            hostname=socket.gethostname(),
            runtime=runtime,
            adapter_name=self.__class__.__name__,
        )

    def get_security_status(self) -> SecurityStatus:
        # Windows-specific virtualization features are NOT APPLICABLE
        hvci = FeatureStatus(applicable=False, available=False, enabled=None, source="not_applicable")
        vbs = FeatureStatus(applicable=False, available=False, enabled=None, source="not_applicable")
        # Secure boot is generally not queryable through standard generic interfaces
        secure_boot = FeatureStatus(applicable=False, available=False, enabled=None, source="generic_unsupported")

        return SecurityStatus(
            hvci=hvci,
            vbs=vbs,
            secure_boot=secure_boot,
        )
