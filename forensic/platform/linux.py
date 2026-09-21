"""Linux platform adapter.

Provides read-only detection of Linux OS information and security features (HVCI, VBS, Secure Boot).
"""

from __future__ import annotations

from pathlib import Path
import platform
import socket
import sys
from typing import Optional

from .base import BasePlatformAdapter, FeatureStatus, PlatformInfo, SecurityStatus


class LinuxPlatformAdapter(BasePlatformAdapter):
    """Concrete adapter for Linux systems.

    All operations are read-only.
    - HVCI and VBS are NOT APPLICABLE on Linux.
    - Secure Boot is queried via standard Linux read-only sysfs / efivars paths.
    """

    def _read_os_release(self) -> dict[str, str]:
        """Safely parse /etc/os-release or /usr/lib/os-release if present."""
        data: dict[str, str] = {}
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                p = Path(path)
                if p.is_file():
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#") or "=" not in line:
                                continue
                            k, v = line.split("=", 1)
                            data[k.strip()] = v.strip().strip('"').strip("'")
                    break
            except Exception:
                continue
        return data

    def _detect_secure_boot(self) -> FeatureStatus:
        """Detect Secure Boot status on Linux via read-only inspection of efivars / sysfs."""
        efivars_dir = Path("/sys/firmware/efi/efivars")
        try:
            if efivars_dir.is_dir():
                for f in efivars_dir.glob("SecureBoot-*"):
                    try:
                        content = f.read_bytes()
                        if len(content) >= 5:
                            is_enabled = content[4] == 1
                            return FeatureStatus(
                                applicable=True,
                                available=True,
                                enabled=is_enabled,
                                source="sysfs:efivars",
                            )
                    except Exception:
                        pass
        except Exception:
            pass

        vars_dir = Path("/sys/firmware/efi/vars")
        try:
            if vars_dir.is_dir():
                for d in vars_dir.glob("SecureBoot-*"):
                    data_file = d / "data"
                    if data_file.is_file():
                        try:
                            content = data_file.read_bytes()
                            if len(content) >= 1:
                                is_enabled = content[0] == 1
                                return FeatureStatus(
                                    applicable=True,
                                    available=True,
                                    enabled=is_enabled,
                                    source="sysfs:vars",
                                )
                        except Exception:
                            pass
        except Exception:
            pass

        efi_dir = Path("/sys/firmware/efi")
        if not efi_dir.exists():
            return FeatureStatus(
                applicable=True,
                available=False,
                enabled=None,
                source="non-efi",
            )

        return FeatureStatus(
            applicable=True,
            available=False,
            enabled=None,
            source=None,
        )

    def get_platform_info(self) -> PlatformInfo:
        uname = platform.uname()
        os_release = self._read_os_release()
        os_name = os_release.get("PRETTY_NAME") or os_release.get("NAME") or uname.system or "Linux"
        os_version = os_release.get("VERSION_ID") or uname.release

        runtime = f"Python {sys.version.split()[0]}"
        return PlatformInfo(
            os_name=os_name,
            os_version=os_version,
            architecture=uname.machine,
            hostname=socket.gethostname(),
            runtime=runtime,
            adapter_name=self.__class__.__name__,
        )

    def get_security_status(self) -> SecurityStatus:
        # HVCI & VBS are Windows-specific virtualization features -> NOT APPLICABLE on Linux
        hvci = FeatureStatus(applicable=False, available=False, enabled=None, source="unsupported_on_linux")
        vbs = FeatureStatus(applicable=False, available=False, enabled=None, source="unsupported_on_linux")
        secure_boot = self._detect_secure_boot()

        return SecurityStatus(
            hvci=hvci,
            vbs=vbs,
            secure_boot=secure_boot,
        )
