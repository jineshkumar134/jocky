"""Platform adapter factory.

Instantiates the appropriate platform adapter based on the host operating system
or an explicitly supplied system name.
"""

from __future__ import annotations

import platform
from typing import Optional

from .base import BasePlatformAdapter
from .fixture import FixturePlatformAdapter
from .generic import GenericPlatformAdapter
from .linux import LinuxPlatformAdapter
from .windows import WindowsPlatformAdapter


class PlatformAdapterFactory:
    """Factory for resolving platform adapters."""

    @staticmethod
    def get_adapter(os_name: Optional[str] = None) -> BasePlatformAdapter:
        """Resolve and instantiate a platform adapter.

        Parameters
        ----------
        os_name:
            Target operating system name (e.g., "Windows", "Linux", "fixture").
            If omitted or None, defaults to `platform.system()`.
        """
        system = (os_name or platform.system() or "").lower()

        if system.startswith("fixture"):
            plat = "linux"
            if "windows" in system:
                plat = "windows"
            elif "generic" in system:
                plat = "generic"
            return FixturePlatformAdapter(platform_name=plat)
        elif system == "windows":
            return WindowsPlatformAdapter()
        elif system == "linux":
            return LinuxPlatformAdapter()
        else:
            return GenericPlatformAdapter()
