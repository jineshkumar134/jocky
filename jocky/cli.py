"""
jocky/cli.py – JOCKY Command-Line Interface
---------------------------------------------
Invocation::

    python -m jocky.cli <path-to-.jky-file> [--tokens] [--show-ir] [--show-llvm] [--execute] [--fixture] [--json]

Flags:
  --tokens     Print the raw token stream after lexing.
  --show-ir    Print the generated JOCKY IR after lowering.
  --show-llvm  Print the generated LLVM IR text after code generation.
  --execute    Execute the JOCKY investigation through the runtime executor.
  --fixture    Use deterministic fixture adapter instead of inspecting the local host.
  --json       Print execution results in structured JSON format.

Exit codes:
  0  – success
  1  – compile / lowering / execution error
  2  – file not found / IO error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from compiler.compiler import compile_source
from compiler.ast.printer import render as render_ast
from compiler.ir.printer import render as render_ir
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.endpoint.local import LocalEndpointAdapter
from forensic.endpoint.base import EndpointResult, FileArtifact, ProcessArtifact, SystemArtifact
from forensic.network.fixture import FixtureNetworkAdapter
from forensic.network.local import LocalNetworkAdapter
from forensic.network.base import NetworkResult, NetworkConnection, NetworkListener, DNSRecord
from runtime.executor.executor import RuntimeExecutor


# ── ANSI colour helpers (disabled when not a TTY) ──────────
def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s

def _green(s: str) -> str: return _c("92", s)
def _red(s: str)   -> str: return _c("91", s)
def _cyan(s: str)  -> str: return _c("96", s)
def _bold(s: str)  -> str: return _c("1",  s)
def _yellow(s: str)-> str: return _c("93", s)


def _banner() -> None:
    print(_bold("\n  ╔══════════════════════════════════════╗"))
    print(_bold("  ║  JOCKY Forensic Investigation DSL   ║"))
    print(_bold("  ╚══════════════════════════════════════╝\n"))

def _divider() -> None:
    print("  " + "─" * 60)


def _print_execution_output(exec_result, is_fixture: bool = False) -> None:
    """Format and print a cybersecurity command-center style execution summary."""
    print(_bold("JOCKY PROGRAM"))
    print("--------------")
    print(f"Case: {_cyan(exec_result.case_id)}")
    adapter_label = "Fixture" if is_fixture else "Local (Read-Only Live)"
    print(f"Host: {_cyan(exec_result.host)}")
    if is_fixture:
        print(f"Mode: {_cyan('Fixture')}")
    print()

    has_endpoint = any(isinstance(r.data, EndpointResult) for r in exec_result.results)
    has_network = any(isinstance(r.data, NetworkResult) for r in exec_result.results)
    has_blockchain = any(hasattr(r.data, "__class__") and r.data.__class__.__name__ == "BlockchainTraceResult" for r in exec_result.results)
    has_vasp = any(hasattr(r.data, "__class__") and r.data.__class__.__name__ == "VASPResult" for r in exec_result.results)
    has_correlation = any(hasattr(r.data, "__class__") and r.data.__class__.__name__ == "CorrelationResult" for r in exec_result.results)
    has_graph = any(hasattr(r.data, "__class__") and r.data.__class__.__name__ == "InvestigationGraph" for r in exec_result.results)
    has_timeline = any(hasattr(r.data, "__class__") and r.data.__class__.__name__ == "InvestigationTimeline" for r in exec_result.results)
    has_risk = any(hasattr(r.data, "__class__") and r.data.__class__.__name__ == "RiskAssessment" for r in exec_result.results)
    has_security = any(r.operation == "CHECK_SECURITY" for r in exec_result.results)
    has_research = any(r.operation == "RESEARCH" for r in exec_result.results)

    print(_bold("EXECUTION PIPELINE"))
    print("------------------")
    print(f"Parsing                 {_green('✓')}")
    print(f"IR Generation           {_green('✓')}")
    print(f"Runtime Execution       {_green('✓')}")
    if has_endpoint:
        print(f"Endpoint Analysis       {_green('✓')}")
    if has_network:
        print(f"Network Analysis        {_green('✓')}")
    if has_blockchain:
        print(f"Blockchain Tracing      {_green('✓')}")
    if has_vasp:
        print(f"VASP Attribution        {_green('✓')}")
    if has_correlation:
        print(f"Correlation Engine      {_green('✓')}")
    if has_graph:
        print(f"Attack Graph Engine     {_green('✓')}")
    if has_timeline:
        print(f"Investigation Timeline  {_green('✓')}")
    if has_risk:
        print(f"Risk Assessment Engine  {_green('✓')}")
    if has_security:
        print(f"Security Pre-Check      {_green('✓')}")
    if has_research:
        print(f"Security Research Lab   {_green('✓')}")
    print()


    # Walk through each operation result
    for op_res in exec_result.results:
        data = op_res.data
        is_bc   = hasattr(data, "__class__") and data.__class__.__name__ == "BlockchainTraceResult"
        is_vasp = hasattr(data, "__class__") and data.__class__.__name__ == "VASPResult"
        is_corr = hasattr(data, "__class__") and data.__class__.__name__ == "CorrelationResult"
        is_graph = hasattr(data, "__class__") and data.__class__.__name__ == "InvestigationGraph"
        is_timeline = hasattr(data, "__class__") and data.__class__.__name__ == "InvestigationTimeline"
        is_risk = hasattr(data, "__class__") and data.__class__.__name__ == "RiskAssessment"
        is_anchor = hasattr(data, "__class__") and data.__class__.__name__ == "EvidenceAnchor"
        is_verify = hasattr(data, "__class__") and data.__class__.__name__ == "VerificationResult"
        is_check_sec = op_res.operation == "CHECK_SECURITY"
        is_research = op_res.operation == "RESEARCH"

        if is_research:
            print(_bold("SECURITY RESEARCH"))
            print("-----------------")
            if isinstance(data, dict):
                sc = data.get("scenario", {})
                bm = data.get("benchmark", {})
                findings = data.get("findings", [])
                cat = sc.get("category", "")
                
                # Specialized Scenario Headers
                if cat == "DRIVER_RISK":
                    print(f"Type: {_yellow('SIMULATED DRIVER RISK')}")
                elif cat == "MEMORY_EXECUTION":
                    print(f"Type: {_yellow('SIMULATED MEMORY EXECUTION')}")
                elif cat == "POLYMORPHISM":
                    print(f"Type: {_cyan('SAFE POLYMORPHISM BENCHMARK')}")
                elif cat == "SECURITY_CONTROL":
                    print(f"Type: {_cyan('SECURITY CONTROL ASSESSMENT')}")
                else:
                    print(f"Type: {_cyan('SAFE NETWORK BEHAVIOR')}")

                print(f"Scenario:           {_cyan(sc.get('scenario_id', ''))}")
                print(f"Mode:               {_yellow('SIMULATION')}")
                print(f"Safety:             {_green('SAFE / SYNTHETIC')}")
                print(f"Observables:        {bm.get('observable_count', len(data.get('observables', [])))}")
                print(f"Findings:           {len(findings)}")
                cov = bm.get('detection_coverage', 0) * 100
                print(f"Detection Coverage: {_green(f'{cov:.0f}%')}")
                print(f"Result Hash:        {_cyan(data.get('result_hash', ''))}")

                if findings:
                    print()
                    print(_bold("Research Findings:"))
                    for f in findings:
                        f_sev = f.get("severity", "LOW")
                        sev_c = _red(f_sev) if f_sev in ("CRITICAL", "HIGH") else (_yellow(f_sev) if f_sev == "MEDIUM" else _green(f_sev))
                        print(f"  • [{sev_c}] {_bold(f.get('rule_id', ''))} (Conf: {f.get('confidence', 1.0):.2f})")
                        print(f"    {f.get('explanation', '')}")
            print()
            continue

        if is_check_sec:
            p_info = None
            sec_status = None
            if isinstance(data, dict):
                p_info = data.get("platform_info")
                sec_status = data.get("security_status")

            if p_info:
                print(_bold("PLATFORM"))
                print(f"OS: {p_info.get('os_name', 'UNKNOWN')}")
                print(f"OS VERSION: {p_info.get('os_version', 'UNKNOWN')}")
                print(f"ARCHITECTURE: {p_info.get('architecture', 'UNKNOWN')}")
                print(f"HOSTNAME: {p_info.get('hostname', 'UNKNOWN')}")
                print(f"RUNTIME: {p_info.get('runtime', 'UNKNOWN')}")
                print(f"ADAPTER: {p_info.get('adapter_name', 'UNKNOWN')}")
                print()

            if sec_status:
                print(_bold("SECURITY PRE-CHECK"))
                for feature_name, label in [("hvci", "HVCI"), ("vbs", "VBS"), ("secure_boot", "SECURE BOOT")]:
                    feat = sec_status.get(feature_name)
                    status_text = "UNKNOWN"
                    if isinstance(feat, dict):
                        if not feat.get("applicable", True):
                            status_text = "NOT APPLICABLE"
                        elif feat.get("available") is False:
                            status_text = "UNKNOWN"
                        elif feat.get("enabled") is True:
                            status_text = "ENABLED"
                        elif feat.get("enabled") is False:
                            status_text = "DISABLED"
                        else:
                            status_text = "UNKNOWN"
                    print(f"{label}: {status_text}")
                print()
            continue

        if is_anchor:
            print(_bold("EVIDENCE ANCHOR"))
            print("---------------")
            print(f"Package Hash: {_cyan(data.package_hash)}")
            print(f"IPFS CID:     {data.ipfs_cid}")
            print(f"EVM Chain ID: {data.chain_id}")
            print(f"EVM TX Hash:  {data.tx_hash}")
            print(f"Anchored At:  {data.anchored_at}")
            print()
            continue
            
        if is_verify:
            print(_bold("EVIDENCE VERIFICATION"))
            print("---------------------")
            
            valid_color = _green("PASS") if data.is_valid else _red("FAIL")
            print(f"Overall Status: [{valid_color}]")
            
            p_match = _green("MATCH") if data.package_hash_match else _red("MISMATCH")
            print(f"Package Hash:   [{p_match}] {data.expected_package_hash[:16]}...")
            
            i_match = _green("MATCH") if data.ipfs_match else _red("MISMATCH")
            print(f"IPFS Content:   [{i_match}]")
            
            e_match = _green("MATCH") if data.evm_match else _red("MISMATCH")
            print(f"EVM Record:     [{e_match}]")
            
            if not data.is_valid and data.errors:
                print()
                print(_bold("Errors:"))
                for err in data.errors:
                    print(f"  - {_red(err)}")
            print()
            continue

        if is_timeline:
            print(_bold("TIMELINE"))
            print("--------")
            events = getattr(data, "events", [])
            print(f"Events: {len(events)}")
            summary = getattr(data, "summary", {})
            earliest = summary.get("first_timestamp")
            latest = summary.get("last_timestamp")
            print(f"First:  {earliest or 'N/A'}")
            print(f"Last:   {latest or 'N/A'}")
            breakdown = summary.get("event_type_counts", {})
            if breakdown:
                print("Breakdown:")
                for ev_type, count in breakdown.items():
                    print(f"- {ev_type}: {count}")
            print()
            continue

        if is_risk:
            print(_bold("RISK ASSESSMENT"))
            print("---------------")
            score = getattr(data, "score", 0)
            sev = getattr(data, "severity", None)
            sev_val = sev.value if hasattr(sev, "value") else str(sev)
            findings = getattr(data, "findings", [])
            
            sev_color = _red(sev_val) if sev_val == "CRITICAL" else (_yellow(sev_val) if sev_val in ("HIGH", "MEDIUM") else _green(sev_val))
            print(f"Score:    {score} / 100")
            print(f"Severity: {sev_color}")
            print(f"Findings: {len(findings)}")
            print()
            if findings:
                print(_bold("Top Findings:"))
                for f in findings:
                    f_sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    f_sev_color = _red(f_sev) if f_sev == "CRITICAL" else (_yellow(f_sev) if f_sev in ("HIGH", "MEDIUM") else _green(f_sev))
                    print(f"- [{f_sev_color}] {_bold(f.title)} (+{f.score})")
                    print(f"  Rule: {f.rule_id} | Confidence: {f.confidence:.2f}")
                    print(f"  {f.explanation}")
                    print()
            continue

        if is_graph:
            print(_bold("INVESTIGATION GRAPH"))
            print("-------------------")
            nodes = getattr(data, "nodes", [])
            edges = getattr(data, "edges", [])
            print(f"Nodes: {len(nodes)}")
            print(f"Edges: {len(edges)}")
            print()

            from graph.queries import get_cross_domain_paths
            paths = get_cross_domain_paths(data)
            if paths:
                primary_path = paths[0]
                print(_bold("PATH:"))
                print()
                for i, node in enumerate(primary_path.nodes):
                    print(f"{node.node_type.value}")
                    if i < len(primary_path.edges):
                        edge = primary_path.edges[i]
                        print(f"↓ {edge.relationship_type}")
                print()
                print(f"Path Confidence: {_cyan(f'{primary_path.confidence:.2f}')}")
            else:
                print("  (No cross-domain path found)")
            print()
            continue

        if is_corr:
            print(_bold("CORRELATIONS"))
            print("------------")
            findings = getattr(data, "findings", [])
            overall_conf = getattr(data, "confidence", 0.0)
            print(f"Overall Chain Confidence: {_cyan(f'{overall_conf:.2f}')}  ({len(findings)} finding(s))")
            print()
            for i, f in enumerate(findings, 1):
                ctype = f.correlation_type.value if hasattr(f.correlation_type, "value") else str(f.correlation_type)
                rel   = f.relationship_type
                conf  = f.confidence
                rule  = f.rule_id
                conf_color = _green(f"{conf:.2f}") if conf >= 0.80 else (_yellow(f"{conf:.2f}") if conf >= 0.60 else _red(f"{conf:.2f}"))
                print(f"  [{i:02d}] {_bold(ctype)}  ({rel})")
                print(f"       Rule:       {rule}")
                print(f"       Confidence: {conf_color}")
                print(f"       Explanation:")
                # Wrap explanation at 70 chars for readability
                words = f.explanation.split()
                line = "         "
                for word in words:
                    if len(line) + len(word) + 1 > 78:
                        print(line)
                        line = "         " + word
                    else:
                        line = line + " " + word if line.strip() else "         " + word
                if line.strip():
                    print(line)
                print()
            continue


        if not isinstance(data, (EndpointResult, NetworkResult)) and not is_bc and not is_vasp:
            # Other / future operations
            header_name = op_res.operation.replace("_", " ")
            print(_bold(header_name))
            print("-" * max(len(header_name), 6))
            status_color = _green("✓") if op_res.status == "SUCCESS" else (_yellow("⚠") if op_res.status == "NOT_IMPLEMENTED" else _red("✗"))
            print(f"Status: {status_color} {op_res.status}")
            if op_res.message:
                print(f"Info:   {op_res.message}")
            print()
            continue


        if isinstance(data, EndpointResult):
            if data.operation == "ANALYZE_FILES":
                print(_bold("FILES"))
                print("-----")
                summary = data.summary
                total = summary.get("total_files_analyzed", len(data.artifacts))
                total_bytes = summary.get("total_bytes", 0)
                target = summary.get("target", "default")
                print(f"Target: {target}")
                print(f"Analyzed {total} file(s) ({total_bytes:,} bytes total)")
                for i, art in enumerate(data.artifacts[:8]):
                    if isinstance(art, FileArtifact):
                        sha_abbr = art.sha256[:16] + "..." if len(art.sha256) > 16 else art.sha256
                        print(f"  [{i+1:02d}] {art.name:<25} ({art.size:>7,} B)  SHA256: {sha_abbr}  [{art.file_type}]")
                        if art.error:
                            print(f"       {_yellow('Notice:')} {art.error}")
                if len(data.artifacts) > 8:
                    print(f"  ... and {len(data.artifacts) - 8} more file(s)")
                print()

            elif data.operation == "ANALYZE_PROCESSES":
                print(_bold("PROCESSES"))
                print("---------")
                summary = data.summary
                total = summary.get("total_processes_analyzed", len(data.artifacts))
                running_cnt = summary.get("running_count", 0)
                print(f"Enumerated {total} process(es) ({running_cnt} active/running)")
                for i, proc in enumerate(data.artifacts[:8]):
                    if isinstance(proc, ProcessArtifact):
                        print(f"  [{i+1:02d}] PID {proc.pid:<6} {proc.name:<22} status: {proc.status:<10} user: {proc.username or 'N/A'}")
                        if proc.error:
                            print(f"       {_yellow('Notice:')} {proc.error}")
                if len(data.artifacts) > 8:
                    print(f"  ... and {len(data.artifacts) - 8} more process(es)")
                print()

            elif data.operation == "ANALYZE_SYSTEM":
                print(_bold("SYSTEM"))
                print("------")
                for art in data.artifacts:
                    if isinstance(art, SystemArtifact):
                        print(f"Hostname:     {art.hostname}")
                        print(f"OS:           {art.os} ({art.architecture})")
                        print(f"Kernel:       {art.kernel}")
                        print(f"Runtime:      {art.runtime}")
                        if art.cpu_count is not None:
                            print(f"CPU Cores:    {art.cpu_count}")
                        if art.memory_total_bytes is not None:
                            gb = art.memory_total_bytes / (1024**3)
                            print(f"Total Memory: {gb:.2f} GB")
                        if art.boot_time:
                            print(f"Boot Time:    {art.boot_time}")
                print()

        elif isinstance(data, NetworkResult):
            print(_bold("NETWORK CONNECTIONS"))
            print("-------------------")
            if not data.connections:
                print("  (No active connections found)")
            for i, conn in enumerate(data.connections[:8]):
                print(f"\n[{i+1:02d}]")
                if conn.process_name:
                    print(f"Process:  {conn.process_name}")
                if conn.pid is not None:
                    print(f"PID:      {conn.pid}")
                print(f"Protocol: {conn.protocol}")
                rem = f"{conn.remote_address}:{conn.remote_port}" if conn.remote_port else str(conn.remote_address)
                print(f"Remote:   {rem}")
                print(f"Status:   {conn.status}")
                if conn.risk_indicators:
                    print(f"Risks:    {', '.join(conn.risk_indicators)}")
            if len(data.connections) > 8:
                print(f"\n  ... and {len(data.connections) - 8} more connection(s)")
            print()

            print(_bold("LISTENING PORTS"))
            print("---------------")
            if not data.listeners:
                print("  (No listening ports found)")
            for i, l in enumerate(data.listeners[:8]):
                print(f"\n[{i+1:02d}]")
                if l.process_name:
                    print(f"Process:  {l.process_name}")
                if l.pid is not None:
                    print(f"PID:      {l.pid}")
                print(f"{l.protocol} {l.local_address}:{l.local_port}")
                print(f"{l.status}")
                if l.risk_indicators:
                    print(f"Risks:    {', '.join(l.risk_indicators)}")
            if len(data.listeners) > 8:
                print(f"\n  ... and {len(data.listeners) - 8} more listener(s)")
            print()

            print(_bold("DNS"))
            print("---")
            if not data.dns_records:
                print("  (No DNS records queried)")
            for d in data.dns_records:
                print(f"\n{d.domain}")
                for addr in d.addresses:
                    print(f"→ {addr}")
                if d.error:
                    print(f"  {_yellow('Notice:')} {d.error}")
            print()

        elif is_bc:
            print(_bold("BLOCKCHAIN TRACE"))
            print("----------------")
            print(f"Seed Address: {_cyan(data.seed_address)} ({data.chain})")
            print(f"Discovered:   {len(data.wallets)} wallet(s), {len(data.transactions)} transaction(s), {len(data.hops)} hop(s)")
            print()
            if data.hops:
                print(_bold("TRANSACTION HOPS"))
                print("----------------")
                for h in data.hops:
                    print(f"  [Hop {h.hop_number}] {_cyan(h.from_wallet)} → {_cyan(h.to_wallet)}")
                    print(f"         {h.amount} {h.asset}  (TX: {h.tx_hash})  Time: {h.timestamp}")
                print()
            if data.wallets:
                print(_bold("IDENTIFIED WALLETS"))
                print("------------------")
                for w in data.wallets:
                    lbl = f" - {w.label}" if w.label else ""
                    print(f"  • {_cyan(w.address)} [{w.wallet_type}]{lbl} (conf: {w.confidence})")
                print()

        elif is_vasp:
            print(_bold("VASP ATTRIBUTION"))
            print("----------------")
            if not data.attributions:
                print("  (No VASP candidates matched for target wallet)")
            for i, attr in enumerate(data.attributions):
                print(f"  [{i+1:02d}] {_bold(attr.name)}  (Score: {_green(f'{attr.score:.2f}')}, Confidence: {attr.confidence:.2f})")
                print(f"       VASP ID: {attr.vasp_id}")
                if attr.reasons:
                    print("       Attribution Reasons:")
                    for r in attr.reasons:
                        print(f"         • {r}")
                if attr.scoring_breakdown:
                    b_str = ", ".join(f"{k}={v}" for k, v in attr.scoring_breakdown.items())
                    print(f"       Scoring breakdown: {b_str}")
                print()

    # Phase 13: CENTRAL INVESTIGATION block
    mgr = exec_result.context.get("investigation_manager")
    if mgr is not None:
        try:
            case = mgr.get_case(exec_result.case_id)
            summary = mgr.generate_summary(exec_result.case_id)
            status_val = summary.status.value if hasattr(summary.status, "value") else str(summary.status)
            print(_bold("CENTRAL INVESTIGATION"))
            print("---------------------")
            print(f"CASE ID:           {_cyan(summary.case_id)}")
            print(f"STATUS:            {status_val}")
            print(f"HOSTS:             {summary.host_count}")
            print(f"EVIDENCE PACKAGES: {summary.evidence_package_count}")
            print(f"EVIDENCE ITEMS:    {summary.evidence_item_count}")
            print(f"CORRELATIONS:      {summary.correlation_count}")
            print(f"RELATIONSHIPS:     {summary.relationship_count}")
            risk_color = _red(str(summary.highest_risk_score)) if summary.highest_risk_score >= 80 else (_yellow(str(summary.highest_risk_score)) if summary.highest_risk_score >= 40 else _green(str(summary.highest_risk_score)))
            print(f"RISK:              {risk_color} / 100")
            print()
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m jocky.cli",
        description="Compile and execute a .jky JOCKY investigation script.",
    )
    ap.add_argument("file", help="Path to the .jky script")
    ap.add_argument(
        "--tokens",
        action="store_true",
        help="Print the token stream produced by the lexer",
    )
    ap.add_argument(
        "--show-ir",
        action="store_true",
        dest="show_ir",
        help="Print the generated JOCKY IR",
    )
    ap.add_argument(
        "--show-llvm",
        action="store_true",
        dest="show_llvm",
        help="Print the generated LLVM IR text",
    )
    ap.add_argument(
        "--execute",
        action="store_true",
        help="Execute the JOCKY investigation script using the forensic runtime",
    )
    ap.add_argument(
        "--fixture",
        action="store_true",
        help="Use deterministic fixture adapter instead of inspecting the local host",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Output runtime execution results as JSON",
    )
    args = ap.parse_args(argv)

    source_path = Path(args.file)

    # ── Read source ────────────────────────────────────────
    try:
        source = source_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(_red(f"  ✗ File not found: {source_path}"))
        return 2
    except OSError as exc:
        print(_red(f"  ✗ Cannot read {source_path}: {exc}"))
        return 2

    # ── Compile (Lex + Parse + IR + LLVM) ───────────────────
    emit_llvm = args.show_llvm
    result = compile_source(source, source_name=str(source_path), emit_llvm=emit_llvm)

    # If parsing failed, report error and exit
    if not result.ok or result.program is None:
        if not args.json:
            _banner()
            print(f"  Source: {_cyan(str(source_path))}\n")
        for err in result.errors:
            print(_red("  ✗ " + err))
        return 1

    # ── Runtime Execution Mode (--execute) ──────────────────
    if args.execute:
        from blockchain.evm.adapter import EVMAdapter
        blockchain_adapter = EVMAdapter()

        if args.fixture:
            endpoint_adapter = FixtureEndpointAdapter(host=result.ir.host.hostname)
            network_adapter = FixtureNetworkAdapter(host=result.ir.host.hostname)
        else:
            endpoint_adapter = LocalEndpointAdapter(host=result.ir.host.hostname)
            network_adapter = LocalNetworkAdapter(host=result.ir.host.hostname)

        executor = RuntimeExecutor(
            result.ir,
            adapter=endpoint_adapter,
            network_adapter=network_adapter,
            blockchain_adapter=blockchain_adapter,
        )
        exec_result = executor.execute()

        if args.json:
            print(json.dumps(exec_result.to_dict(), indent=2))
            return 0

        _banner()
        _print_execution_output(exec_result, is_fixture=args.fixture)
        return 0

    # ── Inspect Modes (Default compilation output) ──────────
    _banner()
    print(f"  Source: {_cyan(str(source_path))}")
    print()

    # Report Lexing
    if result.tokens:
        n = sum(1 for t in result.tokens if t.type.name != "EOF")
        print(_green("  ✓ Lexing successful") + f"  ({n} tokens)")
        if args.tokens:
            print()
            print(_bold("  Token stream:"))
            _divider()
            for tok in result.tokens:
                if tok.type.name == "EOF":
                    continue
                loc = f"L{tok.line:>3}:C{tok.column:<3}"
                print(f"  {loc}  {tok.type.name:<14}  {tok.value!r}")
            print()

    print(_green("  ✓ Parsing successful"))
    print(_green("  ✓ AST generated") + f"  ({len(result.program.body)} top-level nodes)")

    if result.ir is not None:
        print(_green("  ✓ JOCKY IR generated") + f"  ({len(result.ir.operations)} operations)")

    if result.llvm_ir is not None:
        print(_green("  ✓ LLVM IR generated"))

    for warn in result.warnings:
        print(_yellow(f"  ⚠ {warn}"))

    # Print AST
    if not args.show_llvm:
        print()
        print(_bold("  AST:"))
        _divider()
        for line in render_ast(result.program).splitlines():
            print("  " + line)

    # Print IR
    if args.show_ir and result.ir is not None:
        print()
        print(_bold("  JOCKY IR:"))
        _divider()
        for line in render_ir(result.ir).splitlines():
            print("  " + line)

    # Print LLVM
    if args.show_llvm and result.llvm_ir is not None:
        print()
        print(_bold("  LLVM IR:"))
        _divider()
        for line in result.llvm_ir.strip().splitlines():
            print("  " + line)

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
