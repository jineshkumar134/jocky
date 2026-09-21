"""Security pre-check evaluation engine.

Aggregates platform information and security feature verification (HVCI, VBS, Secure Boot)
using the platform adapter abstractions.
"""

from __future__ import annotations

from typing import Optional

from forensic.platform.base import BasePlatformAdapter, PlatformInfo, SecurityStatus
from forensic.platform.factory import PlatformAdapterFactory


class SecurityPrecheck:
    """Performs read-only security posture pre-checks."""

    def __init__(self, adapter: Optional[BasePlatformAdapter] = None):
        self.adapter = adapter or PlatformAdapterFactory.get_adapter()

    def run_check(self) -> tuple[PlatformInfo, SecurityStatus]:
        """Execute the security pre-check and return platform info and security status."""
        platform_info = self.adapter.get_platform_info()
        security_status = self.adapter.get_security_status()
        return platform_info, security_status
