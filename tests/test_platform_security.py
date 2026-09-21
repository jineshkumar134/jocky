"""
tests/test_platform_security.py
---------------------------------
Comprehensive test suite for Phase 12 Platform Abstraction and Security Pre-check:

1. Platform adapter selection via PlatformAdapterFactory (Windows, Linux, Generic).
2. PlatformInfo data structure and field fidelity across adapters.
3. SecurityStatus and FeatureStatus semantics:
   - APPLICABLE vs NOT APPLICABLE
   - AVAILABLE vs UNKNOWN
   - ENABLED vs DISABLED
4. Deterministic JSON fixture loading and validation for Windows, Linux, and Generic platforms.
5. End-to-end AST -> IR -> Runtime execution of CHECK SECURITY.
6. ExecutionResult model verification (platform_info & security_status inclusion).
7. ANALYZE SYSTEM integration with PlatformAdapter.
8. EvidencePackage canonical package_hash invariance (package_hash strictly preserved before and after CHECK SECURITY).
9. CLI output formatting for CHECK SECURITY and --json validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from compiler.compiler import compile_source
from compiler.ast.nodes import CheckSecurityCommand
from compiler.ir.nodes import CheckSecurityOp
from forensic.platform.base import (
    BasePlatformAdapter,
    FeatureStatus,
    PlatformInfo,
    SecurityStatus,
)
from forensic.platform.factory import PlatformAdapterFactory
from forensic.platform.generic import GenericPlatformAdapter
from forensic.platform.linux import LinuxPlatformAdapter
from forensic.platform.windows import WindowsPlatformAdapter
from forensic.security.precheck import SecurityPrecheck
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.network.fixture import FixtureNetworkAdapter
from runtime.executor.executor import RuntimeExecutor
from jocky.cli import main as cli_main


# ──────────────────────────────────────────────────────────
# 1. Platform Adapter Selection
# ──────────────────────────────────────────────────────────

class TestPlatformAdapterFactory:
    def test_factory_resolves_windows_adapter(self):
        adapter = PlatformAdapterFactory.get_adapter("Windows")
        assert isinstance(adapter, WindowsPlatformAdapter)
        assert isinstance(adapter, BasePlatformAdapter)

    def test_factory_resolves_linux_adapter(self):
        adapter = PlatformAdapterFactory.get_adapter("Linux")
        assert isinstance(adapter, LinuxPlatformAdapter)
        assert isinstance(adapter, BasePlatformAdapter)

    def test_factory_resolves_generic_adapter_for_unsupported_os(self):
        adapter = PlatformAdapterFactory.get_adapter("Darwin")
        assert isinstance(adapter, GenericPlatformAdapter)
        assert isinstance(adapter, BasePlatformAdapter)

        adapter_unknown = PlatformAdapterFactory.get_adapter("FreeBSD")
        assert isinstance(adapter_unknown, GenericPlatformAdapter)

    def test_factory_case_insensitivity(self):
        assert isinstance(PlatformAdapterFactory.get_adapter("windows"), WindowsPlatformAdapter)
        assert isinstance(PlatformAdapterFactory.get_adapter("LINUX"), LinuxPlatformAdapter)
        assert isinstance(PlatformAdapterFactory.get_adapter("darwin"), GenericPlatformAdapter)


# ──────────────────────────────────────────────────────────
# 2. Platform Adapter Information & Security Semantics
# ──────────────────────────────────────────────────────────

class TestPlatformAdapterSemantics:
    def test_linux_adapter_security_semantics(self):
        adapter = LinuxPlatformAdapter()
        sec = adapter.get_security_status()

        # HVCI & VBS must be NOT APPLICABLE on Linux
        assert sec.hvci.applicable is False
        assert sec.hvci.available is False
        assert sec.hvci.enabled is None

        assert sec.vbs.applicable is False
        assert sec.vbs.available is False
        assert sec.vbs.enabled is None

        # Secure boot is applicable on Linux (available/enabled depending on host sysfs)
        assert sec.secure_boot.applicable is True

    def test_generic_adapter_security_semantics(self):
        adapter = GenericPlatformAdapter()
        sec = adapter.get_security_status()

        assert sec.hvci.applicable is False
        assert sec.hvci.enabled is None

        assert sec.vbs.applicable is False
        assert sec.vbs.enabled is None

        assert sec.secure_boot.applicable is False
        assert sec.secure_boot.enabled is None

    def test_windows_adapter_security_semantics(self):
        adapter = WindowsPlatformAdapter()
        sec = adapter.get_security_status()

        # HVCI, VBS, Secure Boot are applicable on Windows
        assert sec.hvci.applicable is True
        assert sec.vbs.applicable is True
        assert sec.secure_boot.applicable is True

    def test_platform_info_fields(self):
        adapter = GenericPlatformAdapter()
        info = adapter.get_platform_info()
        assert isinstance(info, PlatformInfo)
        assert info.os_name
        assert info.architecture
        assert info.hostname
        assert "Python" in info.runtime
        assert info.adapter_name == "GenericPlatformAdapter"


# ──────────────────────────────────────────────────────────
# 3. Deterministic Platform Fixtures
# ──────────────────────────────────────────────────────────

class TestPlatformFixtures:
    @pytest.mark.parametrize("os_name", ["windows", "linux", "generic"])
    def test_fixture_schema_and_integrity(self, os_name: str):
        fixture_path = Path("tests/fixtures/platform") / f"{os_name}.json"
        assert fixture_path.exists(), f"Fixture {fixture_path} missing"

        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        assert "platform_info" in data
        assert "security_status" in data

        p_info = data["platform_info"]
        assert "os_name" in p_info
        assert "os_version" in p_info
        assert "architecture" in p_info
        assert "hostname" in p_info
        assert "runtime" in p_info
        assert "adapter_name" in p_info

        sec = data["security_status"]
        for feat_name in ("hvci", "vbs", "secure_boot"):
            assert feat_name in sec
            feat = sec[feat_name]
            assert "applicable" in feat
            assert "available" in feat
            assert "enabled" in feat
            assert "source" in feat

    def test_mock_adapter_from_fixture(self):
        fixture_path = Path("tests/fixtures/platform/linux.json")
        data = json.loads(fixture_path.read_text(encoding="utf-8"))

        p_info = PlatformInfo(**data["platform_info"])
        sec = SecurityStatus(
            hvci=FeatureStatus(**data["security_status"]["hvci"]),
            vbs=FeatureStatus(**data["security_status"]["vbs"]),
            secure_boot=FeatureStatus(**data["security_status"]["secure_boot"]),
        )

        assert p_info.os_name == "Ubuntu 22.04 LTS"
        assert sec.hvci.applicable is False
        assert sec.secure_boot.enabled is True


# ──────────────────────────────────────────────────────────
# 4. Security Pre-check Engine
# ──────────────────────────────────────────────────────────

class TestSecurityPrecheckEngine:
    def test_security_precheck_run(self):
        adapter = GenericPlatformAdapter()
        precheck = SecurityPrecheck(adapter=adapter)
        info, status = precheck.run_check()

        assert isinstance(info, PlatformInfo)
        assert isinstance(status, SecurityStatus)
        assert info.adapter_name == "GenericPlatformAdapter"


# ──────────────────────────────────────────────────────────
# 5. Pipeline & Execution: CHECK SECURITY
# ──────────────────────────────────────────────────────────

class TestCheckSecurityPipeline:
    def test_compile_check_security(self):
        src = """
CASE "INC-SEC-01"
HOST "SEC-HOST"
CHECK SECURITY
"""
        res = compile_source(src)
        assert res.ok is True
        assert res.program is not None
        assert res.ir is not None

        cmd = res.program.body[2]
        assert isinstance(cmd, CheckSecurityCommand)

        op = res.ir.operations[0]
        assert isinstance(op, CheckSecurityOp)
        assert op.kind == "CHECK_SECURITY"

    def test_runtime_execution_check_security(self):
        src = """
CASE "INC-SEC-01"
HOST "SEC-HOST"
CHECK SECURITY
"""
        res = compile_source(src)
        executor = RuntimeExecutor(
            res.ir,
            adapter=FixtureEndpointAdapter(host="SEC-HOST"),
            network_adapter=FixtureNetworkAdapter(host="SEC-HOST"),
            platform_adapter=GenericPlatformAdapter(),
        )
        exec_res = executor.execute()

        assert len(exec_res.results) == 1
        op_res = exec_res.results[0]
        assert op_res.operation == "CHECK_SECURITY"
        assert op_res.status == "SUCCESS"

        # Check execution_result model fields
        assert exec_res.platform_info is not None
        assert exec_res.security_status is not None

        # Check to_dict() serialization
        d = exec_res.to_dict()
        assert "platform_info" in d
        assert "security_status" in d
        assert d["platform_info"]["adapter_name"] == "GenericPlatformAdapter"
        assert d["security_status"]["hvci"]["applicable"] is False


# ──────────────────────────────────────────────────────────
# 6. EvidencePackage Hash Invariance
# ──────────────────────────────────────────────────────────

class TestEvidencePackageHashInvariance:
    def test_package_hash_invariant_with_check_security(self):
        """CHECK SECURITY must NOT modify the evidence package canonical hash."""
        src_baseline = """
CASE "INC-EVID-01"
HOST "LAB-PC-01"
ANALYZE FILES
ANALYZE PROCESSES
ANALYZE NETWORK
"""
        src_with_check = """
CASE "INC-EVID-01"
HOST "LAB-PC-01"
CHECK SECURITY
ANALYZE FILES
ANALYZE PROCESSES
ANALYZE NETWORK
"""
        res_b = compile_source(src_baseline)
        res_c = compile_source(src_with_check)

        fixed_time = "2026-09-12T12:00:00Z"
        net_ad_b = FixtureNetworkAdapter(host="LAB-PC-01")
        net_ad_c = FixtureNetworkAdapter(host="LAB-PC-01")

        with patch("correlation.rules._NOW", return_value=fixed_time):
            exec_b = RuntimeExecutor(
                res_b.ir,
                adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
                network_adapter=net_ad_b,
            ).execute()

            exec_c = RuntimeExecutor(
                res_c.ir,
                adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
                network_adapter=net_ad_c,
            ).execute()

            # Pin completion timestamps and network result collection timestamps across runs
            exec_b.completed_at = fixed_time
            exec_c.completed_at = fixed_time
            for r in exec_b.results:
                if hasattr(r.data, "timestamp"):
                    r.data.timestamp = fixed_time
            for r in exec_c.results:
                if hasattr(r.data, "timestamp"):
                    r.data.timestamp = fixed_time

            pkg_b = exec_b.build_universal_package()
            pkg_c = exec_c.build_universal_package()

        assert pkg_b.verify_package_integrity() is True
        assert pkg_c.verify_package_integrity() is True
        assert pkg_b.package_hash == pkg_c.package_hash
        assert len(pkg_b.evidence) == len(pkg_c.evidence)
        assert len(pkg_b.relationships) == len(pkg_c.relationships)


# ──────────────────────────────────────────────────────────
# 7. ANALYZE SYSTEM Integration with PlatformAdapter
# ──────────────────────────────────────────────────────────

class TestAnalyzeSystemPlatformIntegration:
    def test_analyze_system_obtains_platform_info(self):
        src = """
CASE "INC-SYS-01"
HOST "LAB-PC-01"
ANALYZE SYSTEM
"""
        res = compile_source(src)
        executor = RuntimeExecutor(
            res.ir,
            adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
            network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
            platform_adapter=GenericPlatformAdapter(),
        )
        exec_res = executor.execute()

        assert len(exec_res.results) == 1
        assert exec_res.results[0].operation == "ANALYZE_SYSTEM"
        assert exec_res.platform_info is not None
        assert exec_res.platform_info.adapter_name == "GenericPlatformAdapter"


# ──────────────────────────────────────────────────────────
# 8. CLI Formatting & --json Compatibility
# ──────────────────────────────────────────────────────────

class TestCLIPlatformSecurity:
    def test_cli_check_security_human_readable(self, tmp_path: Path, capsys):
        jky_file = tmp_path / "test_sec.jky"
        jky_file.write_text("""
CASE "INC-CLI-01"
HOST "CLI-HOST"
CHECK SECURITY
""", encoding="utf-8")

        code = cli_main([str(jky_file), "--execute", "--fixture"])
        assert code == 0

        captured = capsys.readouterr().out
        assert "PLATFORM" in captured
        assert "OS:" in captured
        assert "OS VERSION:" in captured
        assert "ARCHITECTURE:" in captured
        assert "HOSTNAME:" in captured
        assert "RUNTIME:" in captured
        assert "ADAPTER:" in captured
        assert "SECURITY PRE-CHECK" in captured
        assert "HVCI:" in captured
        assert "VBS:" in captured
        assert "SECURE BOOT:" in captured

    def test_cli_check_security_json_output(self, tmp_path: Path, capsys):
        jky_file = tmp_path / "test_sec.jky"
        jky_file.write_text("""
CASE "INC-CLI-01"
HOST "CLI-HOST"
CHECK SECURITY
""", encoding="utf-8")

        code = cli_main([str(jky_file), "--execute", "--fixture", "--json"])
        assert code == 0

        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert data["case_id"] == "INC-CLI-01"
        assert "platform_info" in data
        assert "security_status" in data
        assert "operations" in data
        assert data["operations"][0]["operation"] == "CHECK_SECURITY"
        assert data["operations"][0]["status"] == "SUCCESS"
