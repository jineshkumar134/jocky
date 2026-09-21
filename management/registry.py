"""In-memory host registry."""

from __future__ import annotations

from typing import Dict, List, Optional

from .models import HostRecord, HostStatus


class HostRegistry:
    """In-memory registry of :class:`HostRecord` objects keyed by ``host_id``."""

    def __init__(self) -> None:
        self._hosts: Dict[str, HostRecord] = {}

    # --- mutation ---

    def add(self, record: HostRecord) -> None:
        """Register (or replace) a host record."""
        self._hosts[record.host_id] = record

    # --- query ---

    def get(self, host_id: str) -> Optional[HostRecord]:
        return self._hosts.get(host_id)

    def get_by_hostname(self, hostname: str) -> Optional[HostRecord]:
        for r in self._hosts.values():
            if r.hostname == hostname:
                return r
        return None

    def all(self) -> List[HostRecord]:
        return list(self._hosts.values())

    def ids(self) -> List[str]:
        return list(self._hosts.keys())

    def __len__(self) -> int:
        return len(self._hosts)

    def __contains__(self, host_id: str) -> bool:
        return host_id in self._hosts
