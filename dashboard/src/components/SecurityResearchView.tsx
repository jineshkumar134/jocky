import { useState } from 'react';
import { ResearchResultItem, ResearchFindingItem } from '../types';
import { FlaskConical, AlertTriangle, ShieldCheck, Hash, Layers } from 'lucide-react';

interface SecurityResearchProps {
  researchResults: ResearchResultItem[];
}

export const SecurityResearchView = ({ researchResults }: SecurityResearchProps) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(
    researchResults[0]?.scenario.scenario_id || ''
  );
  const [selectedFinding, setSelectedFinding] = useState<ResearchFindingItem | null>(null);

  const selectedResult =
    researchResults.find((r) => r.scenario.scenario_id === selectedScenarioId) || researchResults[0];

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      default:
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    }
  };

  const getCategoryLabel = (category: string) => {
    switch (category) {
      case 'DRIVER_RISK':
        return 'SIMULATED DRIVER RISK';
      case 'MEMORY_EXECUTION':
        return 'SIMULATED MEMORY EXECUTION';
      case 'POLYMORPHISM':
        return 'SAFE POLYMORPHISM BENCHMARK';
      case 'SECURITY_CONTROL':
        return 'SECURITY CONTROL ASSESSMENT';
      default:
        return 'SAFE NETWORK BEHAVIOR';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Safety Notice */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <FlaskConical className="w-5 h-5 text-purple-400" /> Security Research Lab
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Phase 15 safe, controlled research environment for defensive detection engineering and benchmarking.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/30 px-3 py-1.5 rounded-lg text-xs font-mono text-emerald-400">
          <ShieldCheck className="w-4 h-4" />
          <span>SAFE SIMULATION MODE</span>
        </div>
      </div>

      {/* Safety Scope Banner */}
      <div className="p-4 rounded-xl border border-purple-500/30 bg-purple-950/20 text-xs text-purple-200 flex items-start gap-3">
        <AlertTriangle className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="font-semibold block mb-0.5">Defensive Research Lab Boundary:</strong>
          All scenarios execute strictly simulated or synthetic observable generation. No kernel drivers are loaded,
          no memory injection is executed, no security controls are modified, and no external attack infrastructure is contacted.
        </div>
      </div>

      {/* Scenario Selection Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {researchResults.map((item) => {
          const isSelected = item.scenario.scenario_id === selectedResult?.scenario.scenario_id;
          const cov = (item.benchmark.detection_coverage * 100).toFixed(0);
          return (
            <button
              key={item.scenario.scenario_id}
              onClick={() => {
                setSelectedScenarioId(item.scenario.scenario_id);
                setSelectedFinding(null);
              }}
              className={`p-3.5 rounded-xl border text-left transition font-mono ${
                isSelected
                  ? 'border-purple-500/60 bg-purple-950/30 shadow-lg shadow-purple-950/20'
                  : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
              }`}
            >
              <div className="text-[10px] text-purple-400 uppercase font-semibold">
                {getCategoryLabel(item.scenario.category)}
              </div>
              <div className="text-xs font-bold text-slate-200 mt-1 truncate">
                {item.scenario.scenario_id}
              </div>
              <div className="flex items-center justify-between text-[10px] text-slate-500 mt-2">
                <span>Coverage: <strong className="text-emerald-400">{cov}%</strong></span>
                <span>{item.findings.length} finding(s)</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Selected Scenario Details & Findings */}
      {selectedResult && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 font-mono text-xs">
          {/* Scenario Overview & Observables */}
          <div className="lg:col-span-6 space-y-4">
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
              <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] text-purple-400 uppercase tracking-wider block">
                    {getCategoryLabel(selectedResult.scenario.category)}
                  </span>
                  <h3 className="text-sm font-bold text-slate-100 mt-0.5">
                    {selectedResult.scenario.name}
                  </h3>
                  <div className="text-[11px] text-slate-400 mt-1 font-sans">
                    {selectedResult.scenario.description}
                  </div>
                </div>

                <span className="px-2 py-0.5 rounded text-[10px] bg-slate-950 text-emerald-400 border border-emerald-500/30">
                  {selectedResult.scenario.safety_level}
                </span>
              </div>

              {/* Benchmark Summary */}
              <div className="grid grid-cols-3 gap-2 text-[11px]">
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[9px] block">OBSERVABLES</span>
                  <span className="text-slate-200 font-bold">{selectedResult.benchmark.observable_count}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[9px] block">DETECTIONS</span>
                  <span className="text-slate-200 font-bold">{selectedResult.benchmark.detection_count}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[9px] block">BENCHMARK COVERAGE</span>
                  <span className="text-emerald-400 font-bold">
                    {(selectedResult.benchmark.detection_coverage * 100).toFixed(0)}%
                  </span>
                </div>
              </div>

              {/* Result Hash */}
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center gap-2 text-[11px]">
                <Hash className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                <span className="text-slate-400">Result Hash:</span>
                <span className="text-purple-300 truncate" title={selectedResult.result_hash}>
                  {selectedResult.result_hash}
                </span>
              </div>
            </div>

            {/* Synthetic Observables Table */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
              <h4 className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-purple-400" /> Synthetic Research Observables
              </h4>

              <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                {selectedResult.observables.map((obs) => (
                  <div key={obs.observable_id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-cyan-400 font-bold">{obs.observable_id}</span>
                      <span className="text-slate-500 text-[10px]">{obs.observable_type}</span>
                    </div>
                    <pre className="text-[10px] text-slate-400 overflow-x-auto p-1.5 rounded bg-slate-900/60 border border-slate-800/40">
                      {JSON.stringify(obs.attributes, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Defensive Findings & Explainability Inspector */}
          <div className="lg:col-span-6 space-y-4">
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h4 className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                  Defensive Detection Findings ({selectedResult.findings.length})
                </h4>
                <span className="text-[10px] text-slate-500">Deterministic Rule Evaluation</span>
              </div>

              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {selectedResult.findings.map((finding) => {
                  const isSelected = selectedFinding?.finding_id === finding.finding_id;
                  return (
                    <div
                      key={finding.finding_id}
                      onClick={() => setSelectedFinding(finding)}
                      className={`p-3.5 rounded-lg border text-left cursor-pointer transition ${
                        isSelected
                          ? 'border-purple-500/60 bg-purple-950/20'
                          : 'border-slate-800 bg-slate-950 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase border ${getSeverityBadge(finding.severity)}`}>
                              {finding.severity}
                            </span>
                            <span className="font-bold text-slate-200 text-xs">{finding.rule_id}</span>
                          </div>
                          <p className="text-[11px] text-slate-400 mt-1 line-clamp-2 leading-relaxed font-sans">
                            {finding.explanation}
                          </p>
                        </div>

                        <div className="text-right shrink-0">
                          <span className="text-emerald-400 font-bold">{(finding.confidence * 100).toFixed(0)}%</span>
                          <span className="text-[9px] text-slate-500 block">confidence</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Selected Finding Detail Inspector */}
            {selectedFinding && (
              <div className="p-5 rounded-xl border border-purple-500/40 bg-purple-950/20 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="text-[10px] text-purple-300 font-bold uppercase">
                    INSPECTING: {selectedFinding.rule_id}
                  </span>
                  <span className="text-emerald-400 font-semibold">Finding ID: {selectedFinding.finding_id}</span>
                </div>

                <div className="space-y-2">
                  <div className="text-slate-300 leading-relaxed font-sans text-xs">
                    {selectedFinding.explanation}
                  </div>

                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block mb-1">LINKED OBSERVABLES</span>
                    <div className="flex gap-2">
                      {selectedFinding.observable_ids.map((id) => (
                        <span key={id} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400 text-[10px]">
                          {id}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
