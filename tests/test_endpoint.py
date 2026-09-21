"""
tests/test_endpoint.py
----------------------
Comprehensive test suite for Phase 4 JOCKY Endpoint Forensics Runtime:

1. File hashing (calculate_sha256)
2. File metadata extraction (analyze_single_file, classify_file_type)
3. Process result schema (ProcessArtifact)
4. System result schema (SystemArtifact)
5. Fixture endpoint adapter (FixtureEndpointAdapter)
6. Local endpoint adapter where safe (LocalEndpointAdapter)
7. IR → runtime dispatch (RuntimeExecutor & OperationDispatcher)
8. Invalid / unknown operation handling (graceful NOT_IMPLEMENTED)
9. Permission / error handling (non-existent paths, unreadable files)
10. CLI endpoint execution (--execute, --fixture, --json) & Evidence conversion layer
"""

import hashlib
import json
from pathlib import Path
import tempfile
import pytest

from compiler.compiler import compile_source
from compiler.ir.nodes import (
    AnalyzeFilesOp,
    AnalyzeProcessesOp,
    AnalyzeSystemOp,
    BlockchainTraceOp,
    GenerateReportOp,
    HostTarget,
    InvestigationIR,
)
from forensic.endpoint.base import (
    EndpointResult,
    FileArtifact,
    ProcessArtifact,
    SystemArtifact,
)
from forensic.endpoint.files import (
    calculate_sha256,
    classify_file_type,
    analyze_single_file,
    collect_file_artifacts,
)
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.endpoint.local import LocalEndpointAdapter
from forensic.endpoint.processes import collect_process_artifacts
from forensic.endpoint.system import collect_system_artifact
from jocky.cli import main as cli_main
from runtime.executor.dispatcher import OperationDispatcher
from runtime.executor.executor import RuntimeExecutor


# ──────────────────────────────────────────────────────────
# 1. File Hashing
# ──────────────────────────────────────────────────────────

class TestFileHashing:
    def test_calculate_sha256_exact_match(self, tmp_path: Path):
        content = b"JOCKY-CYBERSECURITY-FORENSIC-EVIDENCE-2026"
        expected_hash = hashlib.sha256(content).hexdigest()

        test_file = tmp_path / "sample_evidence.bin"
        test_file.write_bytes(content)

        computed_hash = calculate_sha256(test_file)
        assert computed_hash == expected_hash

    def test_calculate_sha256_empty_file(self, tmp_path: Path):
        empty_file = tmp_path / "empty.dat"
        empty_file.write_bytes(b"")

        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert calculate_sha256(empty_file) == empty_hash


# ──────────────────────────────────────────────────────────
# 2. File Metadata Extraction
# ──────────────────────────────────────────────────────────

class TestFileMetadataExtraction:
    def test_analyze_single_file_metadata(self, tmp_path: Path):
        test_file = tmp_path / "investigation_tool.py"
        test_file.write_text("print('safe forensic scan')\n", encoding="utf-8")

        artifact = analyze_single_file(test_file)
        assert isinstance(artifact, FileArtifact)
        assert artifact.name == "investigation_tool.py"
        assert artifact.extension == ".py"
        assert artifact.file_type == "script"
        assert artifact.size > 0
        assert len(artifact.sha256) == 64
        assert artifact.modified_at != "UNKNOWN"
        assert artifact.error is None

    def test_classify_file_type_categories(self):
        assert classify_file_type(Path("app.exe")) == "executable"
        assert classify_file_type(Path("script.sh")) == "script"
        assert classify_file_type(Path("report.txt")) == "text"
        assert classify_file_type(Path("data.json")) == "data"
        assert classify_file_type(Path("bundle.zip")) == "archive"
        assert classify_file_type(Path("investigation.jky")) == "jocky_script"
        assert classify_file_type(Path("unknown.xyz")) == "other"


# ──────────────────────────────────────────────────────────
# 3. Process Result Schema
# ──────────────────────────────────────────────────────────

class TestProcessResultSchema:
    def test_process_artifact_validation(self):
        proc = ProcessArtifact(
            pid=1234,
            name="security_agent",
            parent_pid=1,
            executable="/usr/bin/security_agent",
            username="investigator",
            start_time="2026-09-13T12:00:00Z",
            status="running",
        )
        assert proc.type == "PROCESS"
        assert proc.pid == 1234
        assert proc.name == "security_agent"
        assert proc.status == "running"

        # Check serialization
        d = proc.model_dump()
        assert d["pid"] == 1234
        assert d["type"] == "PROCESS"


# ──────────────────────────────────────────────────────────
# 4. System Result Schema
# ──────────────────────────────────────────────────────────

class TestSystemResultSchema:
    def test_system_artifact_validation(self):
        sys_art = SystemArtifact(
            hostname="LAB-PC-01",
            os="Linux",
            architecture="x86_64",
            kernel="6.8.0",
            runtime="Python 3.12",
            cpu_count=8,
            memory_total_bytes=16000000000,
            boot_time="2026-09-12T00:00:00Z",
        )
        assert sys_art.type == "SYSTEM"
        assert sys_art.hostname == "LAB-PC-01"
        assert sys_art.os == "Linux"
        assert sys_art.cpu_count == 8

        d = sys_art.model_dump()
        assert d["architecture"] == "x86_64"


# ──────────────────────────────────────────────────────────
# 5. Fixture Endpoint Adapter
# ──────────────────────────────────────────────────────────

class TestFixtureEndpointAdapter:
    def test_fixture_adapter_deterministic_results(self):
        adapter = FixtureEndpointAdapter(host="TEST-LAB-01")

        # Files
        files_res = adapter.analyze_files()
        assert files_res.status == "SUCCESS"
        assert files_res.operation == "ANALYZE_FILES"
        assert len(files_res.artifacts) >= 3
        assert files_res.artifacts[0].name == "ransomware_dropper.bin"

        # Processes
        proc_res = adapter.analyze_processes()
        assert proc_res.status == "SUCCESS"
        assert proc_res.operation == "ANALYZE_PROCESSES"
        assert len(proc_res.artifacts) >= 3
        assert proc_res.artifacts[1].name == "suspicious_miner"

        # System
        sys_res = adapter.analyze_system()
        assert sys_res.status == "SUCCESS"
        assert sys_res.operation == "ANALYZE_SYSTEM"
        assert sys_res.artifacts[0].hostname == "LAB-PC-01"


# ──────────────────────────────────────────────────────────
# 6. Local Endpoint Adapter (Safe Read-Only)
# ──────────────────────────────────────────────────────────

class TestLocalEndpointAdapter:
    def test_local_adapter_system_analysis(self):
        adapter = LocalEndpointAdapter(host="LOCAL-TEST")
        res = adapter.analyze_system()

        assert res.status in ("SUCCESS", "PARTIAL")
        assert len(res.artifacts) == 1
        sys_info = res.artifacts[0]
        assert isinstance(sys_info, SystemArtifact)
        assert sys_info.os
        assert sys_info.architecture
        assert "Python" in sys_info.runtime

    def test_local_adapter_file_analysis(self, tmp_path: Path):
        (tmp_path / "test_a.txt").write_text("file A", encoding="utf-8")
        (tmp_path / "test_b.py").write_text("print('B')", encoding="utf-8")

        adapter = LocalEndpointAdapter(default_scan_dir=tmp_path)
        res = adapter.analyze_files()

        assert res.status == "SUCCESS"
        assert len(res.artifacts) == 2
        names = [a.name for a in res.artifacts]
        assert "test_a.txt" in names
        assert "test_b.py" in names

    def test_local_adapter_process_enumeration(self):
        adapter = LocalEndpointAdapter()
        res = adapter.analyze_processes(max_processes=5)

        assert res.status in ("SUCCESS", "PARTIAL")
        assert len(res.artifacts) > 0
        assert all(isinstance(a, ProcessArtifact) for a in res.artifacts)


# ──────────────────────────────────────────────────────────
# 7. IR → Runtime Dispatch
# ──────────────────────────────────────────────────────────

class TestIRRuntimeDispatch:
    def test_runtime_executor_all_endpoint_commands(self):
        src = """
CASE "CASE-ENDPOINT-TEST"
HOST "ENDPOINT-TEST-HOST"

ANALYZE FILES
ANALYZE PROCESSES
ANALYZE SYSTEM
"""
        comp_res = compile_source(src)
        assert comp_res.ok is True
        assert comp_res.ir is not None

        adapter = FixtureEndpointAdapter(host=comp_res.ir.host.hostname)
        executor = RuntimeExecutor(comp_res.ir, adapter=adapter)
        exec_result = executor.execute()

        assert exec_result.case_id == "CASE-ENDPOINT-TEST"
        assert exec_result.host == "ENDPOINT-TEST-HOST"
        assert len(exec_result.results) == 3
        assert exec_result.summary["successful_operations"] == 3
        assert exec_result.summary["failed_operations"] == 0

        # Check evidence package conversion layer (Section 6)
        evidence_pkg = exec_result.to_evidence_package()
        assert evidence_pkg["case_id"] == "CASE-ENDPOINT-TEST"
        assert len(evidence_pkg["items"]) == 3
        assert evidence_pkg["items"][0]["evidence_class"] == "ENDPOINT_FORENSIC"


# ──────────────────────────────────────────────────────────
# 8. Unimplemented Operation Handling
# ──────────────────────────────────────────────────────────

class TestUnimplementedOperationHandling:
    def test_unimplemented_operations_do_not_crash(self):
        src = """
CASE "CASE-FUTURE-OPS"
HOST "HOST-01"

ANALYZE SYSTEM
BLOCKCHAIN TRACE "0x1234567890abcdef"
GENERATE REPORT
"""
        comp_res = compile_source(src)
        assert comp_res.ok is True

        adapter = FixtureEndpointAdapter(host=comp_res.ir.host.hostname)
        executor = RuntimeExecutor(comp_res.ir, adapter=adapter)
        exec_res = executor.execute()

        assert len(exec_res.results) == 3
        # First op is ANALYZE_SYSTEM (SUCCESS)
        assert exec_res.results[0].status == "SUCCESS"
        # BLOCKCHAIN_TRACE and GENERATE_REPORT are NOT_IMPLEMENTED in Phase 4
        assert exec_res.results[1].status == "NOT_IMPLEMENTED"
        assert exec_res.results[2].status == "NOT_IMPLEMENTED"
        assert "not implemented" in exec_res.results[1].message.lower()


# ──────────────────────────────────────────────────────────
# 9. Permission and Error Handling
# ──────────────────────────────────────────────────────────

class TestPermissionAndErrorHandling:
    def test_nonexistent_directory_handled_gracefully(self, tmp_path: Path):
        fake_path = tmp_path / "does_not_exist_xyz"
        artifacts, errors = collect_file_artifacts(fake_path)

        assert len(artifacts) == 0
        assert len(errors) == 1
        assert "does not exist" in errors[0]

    def test_missing_file_single_scan_handled_gracefully(self, tmp_path: Path):
        missing_file = tmp_path / "ghost.txt"
        artifact = analyze_single_file(missing_file)

        assert artifact.error is not None
        assert artifact.sha256 == "FILE_NOT_FOUND"


# ──────────────────────────────────────────────────────────
# 10. CLI Endpoint Execution
# ──────────────────────────────────────────────────────────

class TestCLIEndpointExecution:
    def test_cli_execute_with_fixture(self, capsys):
        exit_code = cli_main(["examples/endpoint_demo.jky", "--execute", "--fixture"])
        assert exit_code == 0

        captured = capsys.readouterr().out
        assert "JOCKY PROGRAM" in captured
        assert "Case: ENDPOINT-DEMO-001" in captured
        assert "FILES" in captured
        assert "PROCESSES" in captured
        assert "SYSTEM" in captured
        assert "GENERATE REPORT" in captured

    def test_cli_execute_with_fixture_json(self, capsys):
        exit_code = cli_main(["examples/endpoint_demo.jky", "--execute", "--fixture", "--json"])
        assert exit_code == 0

        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert data["case_id"] == "ENDPOINT-DEMO-001"
        assert data["summary"]["total_operations"] == 4
        assert len(data["operations"]) == 4

    def test_cli_execute_live_local(self, capsys):
        exit_code = cli_main(["examples/endpoint_demo.jky", "--execute"])
        assert exit_code == 0

        captured = capsys.readouterr().out
        assert "JOCKY PROGRAM" in captured
        assert "Runtime Execution" in captured
        assert "Endpoint Analysis" in captured
