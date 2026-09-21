"""
JOCKY Security Research Lab — Scenario Definitions & Safe Registry
==================================================================
Provides deterministic registration and generation of safe synthetic research scenarios.
Strictly disallows shell execution, external driver loading, and dangerous payloads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Dict, List, Optional

from research.models import (
    ResearchScenario,
    ResearchObservable,
    ScenarioCategory,
    ResearchSafetyLevel,
)


class ScenarioRegistry:
    """In-memory safe registry of approved research scenarios."""

    def __init__(self) -> None:
        self._scenarios: Dict[str, ResearchScenario] = {}
        self._generators: Dict[str, Callable[[], List[ResearchObservable]]] = {}
        self._register_default_scenarios()

    def register(
        self,
        scenario: ResearchScenario,
        generator: Callable[[], List[ResearchObservable]],
    ) -> None:
        self._scenarios[scenario.scenario_id] = scenario
        self._generators[scenario.scenario_id] = generator

    def get_scenario(self, scenario_id: str) -> Optional[ResearchScenario]:
        return self._scenarios.get(scenario_id)

    def list_scenarios(self) -> List[ResearchScenario]:
        return list(self._scenarios.values())

    def generate_observables(self, scenario_id: str) -> List[ResearchObservable]:
        gen = self._generators.get(scenario_id)
        if not gen:
            raise KeyError(f"Unknown or unregistered research scenario: '{scenario_id}'")
        return gen()

    def _register_default_scenarios(self) -> None:
        # 1. Polymorphism Benchmark Scenario
        def gen_polymorphism() -> List[ResearchObservable]:
            # Deterministic transformation of benign input representations
            base_data = "BENIGN_INSTRUCTION_SEQUENCE_NOP_NOP_ADD"
            return [
                ResearchObservable(
                    observable_id="OBS-POLY-001",
                    observable_type="SYNTHETIC_POLYMORPHIC_TRANSFORMATION",
                    timestamp="2026-09-18T12:00:00Z",
                    source="bench:representation_engine",
                    attributes={
                        "representation_index": 1,
                        "base_input": base_data,
                        "transformed_length": len(base_data) + 12,
                        "entropy_delta": 0.15,
                        "structural_diff_ratio": 0.42,
                    },
                    confidence=1.0,
                    simulated=True,
                ),
                ResearchObservable(
                    observable_id="OBS-POLY-002",
                    observable_type="SYNTHETIC_POLYMORPHIC_TRANSFORMATION",
                    timestamp="2026-09-18T12:00:01Z",
                    source="bench:representation_engine",
                    attributes={
                        "representation_index": 2,
                        "base_input": base_data,
                        "transformed_length": len(base_data) + 24,
                        "entropy_delta": 0.22,
                        "structural_diff_ratio": 0.55,
                    },
                    confidence=1.0,
                    simulated=True,
                ),
            ]

        self.register(
            ResearchScenario(
                scenario_id="synthetic_polymorphism",
                name="Safe Polymorphic Representation Benchmark",
                category=ScenarioCategory.POLYMORPHISM,
                description="Benchmarks detector variation across benign representation transforms without executing payloads.",
                safety_level=ResearchSafetyLevel.SAFE_BENCHMARK,
                simulated=True,
                expected_observables=["SYNTHETIC_POLYMORPHIC_TRANSFORMATION"],
            ),
            gen_polymorphism,
        )

        # 2. Synthetic Memory Execution Scenario
        def gen_memory() -> List[ResearchObservable]:
            return [
                ResearchObservable(
                    observable_id="OBS-MEM-001",
                    observable_type="SYNTHETIC_MEMORY_ALLOCATION",
                    timestamp="2026-09-18T12:05:00Z",
                    source="sim:virtual_allocator",
                    attributes={
                        "size": 4096,
                        "allocation_type": "MEM_COMMIT | MEM_RESERVE",
                        "protection": "PAGE_EXECUTE_READWRITE",
                        "simulated_tag": "RWX_MOCK_REGION",
                    },
                    confidence=1.0,
                    simulated=True,
                ),
                ResearchObservable(
                    observable_id="OBS-MEM-002",
                    observable_type="SYNTHETIC_MEMORY_ALLOCATION",
                    timestamp="2026-09-18T12:05:01Z",
                    source="sim:virtual_allocator",
                    attributes={
                        "size": 8192,
                        "allocation_type": "MEM_COMMIT",
                        "protection": "PAGE_READONLY",
                        "simulated_tag": "READ_ONLY_DATA",
                    },
                    confidence=1.0,
                    simulated=True,
                ),
            ]

        self.register(
            ResearchScenario(
                scenario_id="synthetic_memory_execution",
                name="Simulated Memory Allocation Research",
                category=ScenarioCategory.MEMORY_EXECUTION,
                description="Simulates telemetry events for RWX allocation detection without injecting code or touching memory.",
                safety_level=ResearchSafetyLevel.SAFE_SYNTHETIC,
                simulated=True,
                expected_observables=["SYNTHETIC_MEMORY_ALLOCATION"],
            ),
            gen_memory,
        )

        # 3. Synthetic Driver / BYOVD Risk Scenario
        def gen_driver() -> List[ResearchObservable]:
            return [
                ResearchObservable(
                    observable_id="OBS-DRV-001",
                    observable_type="SYNTHETIC_DRIVER_RECORD",
                    timestamp="2026-09-18T12:10:00Z",
                    source="sim:driver_catalog",
                    attributes={
                        "driver_name": "gdrv_vulnerable_mock.sys",
                        "publisher": "Generic Third-Party Vendor",
                        "signed": True,
                        "vulnerable_indicator": True,
                        "cve_reference": "CVE-2018-19320 (Simulated Reference)",
                    },
                    confidence=1.0,
                    simulated=True,
                ),
                ResearchObservable(
                    observable_id="OBS-DRV-002",
                    observable_type="SYNTHETIC_DRIVER_RECORD",
                    timestamp="2026-09-18T12:10:01Z",
                    source="sim:driver_catalog",
                    attributes={
                        "driver_name": "clean_disk_filter.sys",
                        "publisher": "Operating System Vendor",
                        "signed": True,
                        "vulnerable_indicator": False,
                    },
                    confidence=1.0,
                    simulated=True,
                ),
            ]

        self.register(
            ResearchScenario(
                scenario_id="synthetic_driver_risk",
                name="Simulated Driver Vulnerability & BYOVD Risk",
                category=ScenarioCategory.DRIVER_RISK,
                description="Classifies driver risk against synthetic catalog indicators without loading or communicating with drivers.",
                safety_level=ResearchSafetyLevel.SAFE_SYNTHETIC,
                simulated=True,
                expected_observables=["SYNTHETIC_DRIVER_RECORD"],
            ),
            gen_driver,
        )

        # 4. Security Control Assessment Scenario
        def gen_sec_controls() -> List[ResearchObservable]:
            return [
                ResearchObservable(
                    observable_id="OBS-SEC-001",
                    observable_type="SECURITY_CONTROL_STATE",
                    timestamp="2026-09-18T12:15:00Z",
                    source="sim:security_posture",
                    attributes={
                        "feature": "HVCI",
                        "status": "DISABLED",
                        "evaluated_control": "Hypervisor-Protected Code Integrity",
                    },
                    confidence=1.0,
                    simulated=True,
                ),
                ResearchObservable(
                    observable_id="OBS-SEC-002",
                    observable_type="SECURITY_CONTROL_STATE",
                    timestamp="2026-09-18T12:15:01Z",
                    source="sim:security_posture",
                    attributes={
                        "feature": "SECURE_BOOT",
                        "status": "UNKNOWN",
                        "evaluated_control": "UEFI Secure Boot",
                    },
                    confidence=1.0,
                    simulated=True,
                ),
            ]

        self.register(
            ResearchScenario(
                scenario_id="synthetic_security_controls",
                name="Security Control Evaluation Simulation",
                category=ScenarioCategory.SECURITY_CONTROL,
                description="Assesses security posture states (ENABLED/DISABLED/UNKNOWN/NOT APPLICABLE) without mutating controls.",
                safety_level=ResearchSafetyLevel.SAFE_INSPECTION,
                simulated=True,
                expected_observables=["SECURITY_CONTROL_STATE"],
            ),
            gen_sec_controls,
        )

        # 5. Safe Network Behavior Simulation Scenario
        def gen_network() -> List[ResearchObservable]:
            return [
                ResearchObservable(
                    observable_id="OBS-NET-001",
                    observable_type="SYNTHETIC_NETWORK_CONNECTION",
                    timestamp="2026-09-18T12:20:00Z",
                    source="sim:network_flow",
                    attributes={
                        "remote_ip": "198.51.100.42",
                        "remote_port": 8443,
                        "protocol": "TCP",
                        "is_external": True,
                        "simulated_label": "TEST_NET_2_DOCUMENTATION_RANGE",
                    },
                    confidence=1.0,
                    simulated=True,
                ),
                ResearchObservable(
                    observable_id="OBS-NET-002",
                    observable_type="SYNTHETIC_NETWORK_CONNECTION",
                    timestamp="2026-09-18T12:20:01Z",
                    source="sim:network_flow",
                    attributes={
                        "remote_ip": "127.0.0.1",
                        "remote_port": 8080,
                        "protocol": "TCP",
                        "is_external": False,
                        "simulated_label": "LOOPBACK_INTERNAL",
                    },
                    confidence=1.0,
                    simulated=True,
                ),
            ]

        self.register(
            ResearchScenario(
                scenario_id="synthetic_network_behavior",
                name="Safe Network Flow Behavior Simulation",
                category=ScenarioCategory.NETWORK_BEHAVIOR,
                description="Evaluates egress detection rules against documentation IP space without transmitting packets.",
                safety_level=ResearchSafetyLevel.SAFE_SYNTHETIC,
                simulated=True,
                expected_observables=["SYNTHETIC_NETWORK_CONNECTION"],
            ),
            gen_network,
        )
