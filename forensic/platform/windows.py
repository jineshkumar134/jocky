"""Windows platform adapter.

Provides read‑only detection of OS information and security features (HVCI, VBS, Secure Boot).
"""

from __future__ import annotations

import platform
import socket
import sys
from typing import Optional

from .base import BasePlatformAdapter, FeatureStatus, PlatformInfo, SecurityStatus


class WindowsPlatformAdapter(BasePlatformAdapter):
    """Concrete adapter for Windows systems.

    All operations are read‑only. Security features are queried via the registry if available.
    """

    def _read_registry_bool(self, path: str, name: str) -> Optional[bool]:
        """Safely read a DWORD registry value and interpret as bool.

        Returns ``None`` if the key/value cannot be read.
        """
        try:
            import winreg  # type: ignore
        except Exception:
            return None
        try:
            hive_str, sub_path = path.split("\\", 1)
            hive = getattr(winreg, hive_str)
            with winreg.OpenKey(hive, sub_path) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return bool(value)
        except Exception:
            return None

    def get_platform_info(self) -> PlatformInfo:
        uname = platform.uname()
        runtime = f"Python {sys.version.split()[0]}"
        return PlatformInfo(
            os_name=uname.system,
            os_version=uname.version,
            architecture=uname.machine,
            hostname=socket.gethostname(),
            runtime=runtime,
            adapter_name=self.__class__.__name__,
        )

    def get_security_status(self) -> SecurityStatus:
        # HVCI: registry key = HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity
        hvci_enabled = self._read_registry_bool(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            "EnableVirtualizationBasedSecurity",
        )
        # VBS: same key contains "RequirePlatformSecurityFeatures"
        vbs_enabled = self._read_registry_bool(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            "RequirePlatformSecurityFeatures",
        )
        # Secure Boot: HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
        secure_boot = self._read_registry_bool(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot",
            "State",
        )
        return SecurityStatus(
            hvci=FeatureStatus(applicable=True, available=hvci_enabled is not None, enabled=hvci_enabled, source="registry" if hvci_enabled is not None else None),
            vbs=FeatureStatus(applicable=True, available=vbs_enabled is not None, enabled=vbs_enabled, source="registry" if vbs_enabled is not None else None),
            secure_boot=FeatureStatus(applicable=True, available=secure_boot is not None, enabled=secure_boot, source="registry" if secure_boot is not None else None),
        )
