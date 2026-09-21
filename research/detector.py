"""
JOCKY Security Research Lab — Defensive Detection Rules Engine
=============================================================
Evaluates synthetic research observables against deterministic, explainable
defensive detection rules. Zero black-box ML, zero evasion capabilities.
"""

from __future__ import annotations

import hashlib
from typing import List

from research.models import (
    ResearchObservable,
    ResearchFinding,
    ResearchSeverity,
)


class ResearchDetector:
    """
    Evaluates research observables against deterministic detection signatures.
    Produces strictly explainable findings.
    """

    def evaluate(self, scenario_id: str, observables: List[ResearchObservable]) -> List[ResearchFinding]:
        findings: List[ResearchFinding] = []

        for obs in observables:
            t = obs.observable_type

            # Rule 1: Synthetic Executable Memory Allocation
            if t == "SYNTHETIC_MEMORY_ALLOCATION":
                prot = obs.attributes.get("protection", "")
                if "EXECUTE" in prot:
                    fid = self._generate_id("RULE_SYNTHETIC_EXECUTABLE_MEMORY", obs.observable_id)
                    findings.append(
                        ResearchFinding(
                            finding_id=fid,
                            rule_id="RULE_SYNTHETIC_EXECUTABLE_MEMORY",
                            severity=ResearchSeverity.HIGH,
                            confidence=0.95,
                            explanation=(
                                f"Observed synthetic memory region allocated with executable permissions: '{prot}'. "
                                "In defensive analysis, non-image executable memory regions indicate potential dynamic code execution."
                            ),
                            observable_ids=[obs.observable_id],
                            simulated=True,
                            metadata={"protection": prot, "size": obs.attributes.get("size")},
                        )
                    )

            # Rule 2: Synthetic Driver Vulnerability Risk
            elif t == "SYNTHETIC_DRIVER_RECORD":
                is_vulnerable = obs.attributes.get("vulnerable_indicator", False)
                is_signed = obs.attributes.get("signed", True)
                driver_name = obs.attributes.get("driver_name", "unknown.sys")

                if is_vulnerable:
                    fid = self._generate_id("RULE_SYNTHETIC_DRIVER_RISK", obs.observable_id)
                    findings.append(
                        ResearchFinding(
                            finding_id=fid,
                            rule_id="RULE_SYNTHETIC_DRIVER_RISK",
                            severity=ResearchSeverity.CRITICAL if not is_signed else ResearchSeverity.HIGH,
                            confidence=1.0,
                            explanation=(
                                f"Synthetic driver '{driver_name}' matches known vulnerable driver blocklist indicator. "
                                "Simulates defensive BYOVD risk scoring without actual driver execution."
                            ),
                            observable_ids=[obs.observable_id],
                            simulated=True,
                            metadata={"driver_name": driver_name, "signed": is_signed},
                        )
                    )

            # Rule 3: Security Control Posture Assessment
            elif t == "SECURITY_CONTROL_STATE":
                feature = obs.attributes.get("feature", "unknown")
                status = obs.attributes.get("status", "UNKNOWN")

                if status == "DISABLED":
                    fid = self._generate_id("RULE_SECURITY_CONTROL_STATE", obs.observable_id)
                    findings.append(
                        ResearchFinding(
                            finding_id=fid,
                            rule_id="RULE_SECURITY_CONTROL_STATE",
                            severity=ResearchSeverity.HIGH,
                            confidence=1.0,
                            explanation=(
                                f"Hardware-enforced security control '{feature}' observed in DISABLED state. "
                                "Weakens endpoint kernel isolation posture."
                            ),
                            observable_ids=[obs.observable_id],
                            simulated=obs.simulated,
                            metadata={"feature": feature, "status": status},
                        )
                    )
                elif status == "UNKNOWN":
                    fid = self._generate_id("RULE_SECURITY_CONTROL_STATE", obs.observable_id)
                    findings.append(
                        ResearchFinding(
                            finding_id=fid,
                            rule_id="RULE_SECURITY_CONTROL_STATE",
                            severity=ResearchSeverity.LOW,
                            confidence=0.8,
                            explanation=(
                                f"Hardware security control '{feature}' status could not be evaluated (UNKNOWN). "
                                "Postural status undetermined; not marked as disabled."
                            ),
                            observable_ids=[obs.observable_id],
                            simulated=obs.simulated,
                            metadata={"feature": feature, "status": status},
                        )
                    )

            # Rule 4: Synthetic Network Outbound Connection
            elif t == "SYNTHETIC_NETWORK_CONNECTION":
                remote_ip = obs.attributes.get("remote_ip", "")
                remote_port = obs.attributes.get("remote_port", 0)
                is_external = obs.attributes.get("is_external", False)

                if is_external:
                    fid = self._generate_id("RULE_EXTERNAL_SYNTHETIC_CONNECTION", obs.observable_id)
                    findings.append(
                        ResearchFinding(
                            finding_id=fid,
                            rule_id="RULE_EXTERNAL_SYNTHETIC_CONNECTION",
                            severity=ResearchSeverity.MEDIUM,
                            confidence=0.90,
                            explanation=(
                                f"Synthetic network flow detected to external documentation IP '{remote_ip}:{remote_port}'. "
                                "Simulates perimeter egress detection without contacting real infrastructure."
                            ),
                            observable_ids=[obs.observable_id],
                            simulated=True,
                            metadata={"remote_ip": remote_ip, "port": remote_port},
                        )
                    )

            # Rule 5: Polymorphic Representation Variation
            elif t == "SYNTHETIC_POLYMORPHIC_TRANSFORMATION":
                entropy_delta = obs.attributes.get("entropy_delta", 0.0)
                structural_diff = obs.attributes.get("structural_diff_ratio", 0.0)

                if structural_diff > 0.3:
                    fid = self._generate_id("RULE_POLYMORPHIC_REPRESENTATION", obs.observable_id)
                    findings.append(
                        ResearchFinding(
                            finding_id=fid,
                            rule_id="RULE_POLYMORPHIC_REPRESENTATION",
                            severity=ResearchSeverity.LOW,
                            confidence=0.85,
                            explanation=(
                                f"Structural variation ratio ({structural_diff:.2f}) observed across benign representations. "
                                "Demonstrates benign format divergence under deterministic benchmarking."
                            ),
                            observable_ids=[obs.observable_id],
                            simulated=True,
                            metadata={"entropy_delta": entropy_delta, "diff_ratio": structural_diff},
                        )
                    )

        return findings

    def _generate_id(self, rule_id: str, obs_id: str) -> str:
        h = hashlib.sha256(f"{rule_id}|{obs_id}".encode()).hexdigest()[:10]
        return f"RFIND-{h}"
