"""Platform adapter factory.

Instantiates the appropriate platform adapter based on the host operating system
or an explicitly supplied system name.
"""

from __future__ import annotations

import platform
from typing import Optional

from .base import BasePlatformAdapter
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
            Target operating system name (e.g., "Windows", "Linux").
            If omitted or None, defaults to `platform.system()`.
        """
        system = (os_name or platform.system() or "").lower()

        if system == "windows":
            return WindowsPlatformAdapter()
        elif system == "linux":
            return LinuxPlatformAdapter()
        else:
            return GenericPlatformAdapter()
