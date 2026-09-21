import React, { useState } from 'react';
import { RiskData, RiskFinding } from '../types';
import { Shield } from 'lucide-react';

interface RiskAssessmentProps {
  riskData: RiskData;
}

export const RiskAssessmentView: React.FC<RiskAssessmentProps> = ({ riskData }) => {
  const [selectedFinding, setSelectedFinding] = useState<RiskFinding | null>(riskData.findings[0] || null);

  const rawSev = typeof riskData.severity === 'object' ? riskData.severity.value : riskData.severity;
  const severityStr = String(rawSev || 'LOW').toUpperCase();

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
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

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Shield className="w-5 h-5 text-orange-400" /> Deterministic Risk Assessment
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Phase 10 explainable scoring engine. Zero black-box ML; findings mapped to explicit rule weights.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-baseline gap-2 bg-slate-900 border border-slate-800 px-4 py-2 rounded-xl">
            <span className="text-xs text-slate-400 font-mono">Overall Score:</span>
            <span className="text-2xl font-bold font-mono text-slate-100">{riskData.score}</span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>

          <div className={`px-3 py-2 rounded-xl font-mono text-xs font-bold uppercase border ${getSeverityBadge(severityStr)}`}>
            {severityStr}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Findings List */}
        <div className="lg:col-span-6 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 pb-1">
            <span>DISCOVERED FINDINGS ({riskData.findings.length})</span>
            <span>WEIGHT / CONFIDENCE</span>
          </div>

          <div className="space-y-2 max-h-[580px] overflow-y-auto pr-1">
            {riskData.findings.map((finding) => {
              const isSelected = selectedFinding?.finding_id === finding.finding_id;
              const fSev = typeof finding.severity === 'object' ? finding.severity.value : finding.severity;
              const fSevStr = String(fSev || 'LOW').toUpperCase();

              return (
                <div
                  key={finding.finding_id}
                  onClick={() => setSelectedFinding(finding)}
                  className={`p-4 rounded-xl border text-left cursor-pointer transition ${
                    isSelected
                      ? 'border-orange-500/60 bg-orange-950/20'
                      : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getSeverityBadge(fSevStr)}`}>
                          {fSevStr}
                        </span>
                        <h4 className="font-bold text-xs text-slate-200">{finding.title}</h4>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 mt-1">Rule: {finding.rule_id}</div>
                    </div>

                    <div className="text-right font-mono shrink-0">
                      <div className="text-sm font-bold text-orange-400">+{finding.score}</div>
                      <div className="text-[10px] text-slate-500">{(finding.confidence * 100).toFixed(0)}% conf</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Finding Detail / Explainability */}
        <div className="lg:col-span-6 p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4 font-mono text-xs">
          {selectedFinding ? (
            <>
              <div className="border-b border-slate-800 pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-orange-400 uppercase tracking-wider block">
                    RULE ID: {selectedFinding.rule_id}
                  </span>
                  <span className="text-orange-400 font-bold text-sm">+{selectedFinding.score} Points</span>
                </div>
                <h3 className="text-base font-bold text-slate-100 mt-1">{selectedFinding.title}</h3>
                <span className="text-slate-400 text-[11px] mt-0.5 block">Finding ID: {selectedFinding.finding_id}</span>
              </div>

              <div className="space-y-3">
                <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <div className="text-[10px] text-slate-500 uppercase tracking-wider">EXPLAINABLE RATIONALE</div>
                  <p className="text-slate-300 leading-relaxed text-xs">{selectedFinding.explanation}</p>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500">FINDING CONFIDENCE</div>
                    <div className="text-emerald-400 text-sm font-bold mt-1">
                      {(selectedFinding.confidence * 100).toFixed(0)}%
                    </div>
                    <div className="text-[10px] text-slate-500 mt-0.5">Distinguished from overall risk score</div>
                  </div>

                  <div className="p-3 rounded bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500">WEIGHT CONTRIBUTION</div>
                    <div className="text-orange-400 text-sm font-bold mt-1">+{selectedFinding.score}</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">Bounded score impact</div>
                  </div>
                </div>

                {selectedFinding.evidence_ids && selectedFinding.evidence_ids.length > 0 && (
                  <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">LINKED EVIDENCE GROUNDING</div>
                    <div className="space-y-1">
                      {selectedFinding.evidence_ids.map((id) => (
                        <div key={id} className="text-cyan-400 text-xs">
                          &bull; {id}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-center py-24 text-slate-500 font-mono">
              Select a finding to inspect deterministic rule explanation.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
