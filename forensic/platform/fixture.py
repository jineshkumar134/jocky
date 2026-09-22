"""Fixture Platform Adapter for deterministic offline and synthetic investigations.

Implements BasePlatformAdapter using deterministic fixture data to ensure platform
and security status consistency regardless of the host environment running the server.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .base import BasePlatformAdapter, FeatureStatus, PlatformInfo, SecurityStatus

_DEFAULT_FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "platform"


class FixturePlatformAdapter(BasePlatformAdapter):
    """Deterministic platform adapter loaded from fixture data."""

    def __init__(
        self,
        platform_name: str = "linux",
        hostname: Optional[str] = None,
        fixture_dir: Optional[Path] = None,
    ) -> None:
        self.platform_name = platform_name.lower()
        self.hostname_override = hostname
        self.fixture_dir = fixture_dir or _DEFAULT_FIXTURE_DIR
        self._load_fixture()

    def _load_fixture(self) -> None:
        fixture_file = self.fixture_dir / f"{self.platform_name}.json"
        if fixture_file.exists():
            try:
                data = json.loads(fixture_file.read_text(encoding="utf-8"))
                p_info = data.get("platform_info", {})
                hostname = self.hostname_override or p_info.get("hostname", "LAB-PC-01")
                self._platform_info = PlatformInfo(
                    os_name=p_info.get("os_name", "Linux"),
                    os_version=p_info.get("os_version", "Ubuntu 22.04 LTS"),
                    architecture=p_info.get("architecture", "x86_64"),
                    hostname=hostname,
                    runtime=p_info.get("runtime", "Python 3.12.3"),
                    adapter_name=p_info.get("adapter_name", "LinuxPlatformAdapter"),
                )
                sec_dict = data.get("security_status", {})
                self._security_status = SecurityStatus(
                    hvci=FeatureStatus(**sec_dict.get("hvci", {"applicable": False, "available": False, "enabled": None, "source": "unsupported_on_linux"})),
                    vbs=FeatureStatus(**sec_dict.get("vbs", {"applicable": False, "available": False, "enabled": None, "source": "unsupported_on_linux"})),
                    secure_boot=FeatureStatus(**sec_dict.get("secure_boot", {"applicable": True, "available": True, "enabled": True, "source": "sysfs:efivars"})),
                )
                return
            except Exception:
                pass

        # Fallback Linux x86_64 platform info
        hostname = self.hostname_override or "LAB-PC-01"
        self._platform_info = PlatformInfo(
            os_name="Linux",
            os_version="Ubuntu 22.04 LTS",
            architecture="x86_64",
            hostname=hostname,
            runtime="Python 3.12.3",
            adapter_name="LinuxPlatformAdapter",
        )
        self._security_status = SecurityStatus(
            hvci=FeatureStatus(applicable=False, available=False, enabled=None, source="unsupported_on_linux"),
            vbs=FeatureStatus(applicable=False, available=False, enabled=None, source="unsupported_on_linux"),
            secure_boot=FeatureStatus(applicable=True, available=True, enabled=True, source="sysfs:efivars"),
        )

    def get_platform_info(self) -> PlatformInfo:
        return self._platform_info

    def get_security_status(self) -> SecurityStatus:
        return self._security_status
