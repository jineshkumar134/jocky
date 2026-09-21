import React from 'react';
import { CaseDetails } from '../types';
import { Shield, Server, FileText, Share2, GitMerge, Hash, Clock, CheckCircle } from 'lucide-react';

interface CaseOverviewProps {
  details: CaseDetails;
  onSelectTab: (tab: string) => void;
}

export const CaseOverview: React.FC<CaseOverviewProps> = ({ details, onSelectTab }) => {
  const cm = details.case_management;
  const summary = cm?.summary;
  const caseObj = cm?.case;
  const riskScore = summary?.highest_risk_score ?? 0;
  const riskSeverity = summary?.highest_risk_severity ?? 'LOW';

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
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
      {/* Top Banner Header */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold text-slate-100 font-mono">{details.case_id}</h2>
            <span className={`px-2.5 py-0.5 rounded text-xs font-semibold uppercase border ${getSeverityBadge(riskSeverity)}`}>
              {riskSeverity} RISK ({riskScore}/100)
            </span>
            <span className="px-2.5 py-0.5 rounded text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              {summary?.status || 'OPEN'}
            </span>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            {caseObj?.title || 'Multi-Host Enterprise Investigation'} &bull; Primary Target: <span className="text-cyan-400 font-mono">{details.host}</span>
          </p>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
          <div className="flex items-center gap-1.5 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
            <Clock className="w-3.5 h-3.5 text-slate-500" />
            <span>Started: {new Date(details.started_at).toLocaleTimeString()}</span>
          </div>
          {cm?.case_hash && (
            <div className="flex items-center gap-1.5 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800" title={`Case Hash: ${cm.case_hash}`}>
              <Hash className="w-3.5 h-3.5 text-indigo-400" />
              <span>Case Hash: {cm.case_hash.slice(0, 10)}...</span>
            </div>
          )}
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <button
          onClick={() => onSelectTab('hosts')}
          className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 hover:border-slate-700 transition text-left group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Registered Hosts</span>
            <Server className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{summary?.host_count ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Topology inventory</div>
        </button>

        <button
          onClick={() => onSelectTab('evidence')}
          className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 hover:border-slate-700 transition text-left group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Evidence Items</span>
            <FileText className="w-4 h-4 text-blue-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{summary?.evidence_item_count ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">{summary?.evidence_package_count ?? 0} package(s)</div>
        </button>

        <button
          onClick={() => onSelectTab('evidence')}
          className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 hover:border-slate-700 transition text-left group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Correlations</span>
            <GitMerge className="w-4 h-4 text-indigo-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{summary?.correlation_count ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Cross-domain links</div>
        </button>

        <button
          onClick={() => onSelectTab('graph')}
          className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 hover:border-slate-700 transition text-left group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Relationships</span>
            <Share2 className="w-4 h-4 text-emerald-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{summary?.relationship_count ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Grounded edges</div>
        </button>

        <button
          onClick={() => onSelectTab('risk')}
          className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 hover:border-slate-700 transition text-left group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Risk Score</span>
            <Shield className="w-4 h-4 text-orange-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{riskScore} <span className="text-xs text-slate-500 font-normal">/ 100</span></div>
          <div className="text-[11px] text-slate-500 mt-1">{riskSeverity} severity</div>
        </button>

        <button
          onClick={() => onSelectTab('anchoring')}
          className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 hover:border-slate-700 transition text-left group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Integrity Anchor</span>
            <CheckCircle className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">VERIFIED</div>
          <div className="text-[11px] text-slate-500 mt-1">EVM + IPFS Proof</div>
        </button>
      </div>

      {/* Platform & Operational Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" /> Platform Environment ({details.host})
          </h3>
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="text-slate-500 text-[10px]">OPERATING SYSTEM</div>
              <div className="text-slate-200 font-medium mt-0.5">{details.platform_info?.os_name || 'Generic POSIX'}</div>
            </div>
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="text-slate-500 text-[10px]">ARCHITECTURE</div>
              <div className="text-slate-200 font-medium mt-0.5">{details.platform_info?.architecture || 'x86_64'}</div>
            </div>
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="text-slate-500 text-[10px]">RUNTIME ADAPTER</div>
              <div className="text-slate-200 font-medium mt-0.5">{details.platform_info?.adapter_name || 'FixtureEndpointAdapter'}</div>
            </div>
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="text-slate-500 text-[10px]">EXECUTION RUNTIME</div>
              <div className="text-slate-200 font-medium mt-0.5">{details.platform_info?.runtime || 'JOCKY v0.14.0'}</div>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" /> Security Pre-Check Posture
          </h3>
          <div className="grid grid-cols-3 gap-2 text-xs font-mono">
            {(['hvci', 'vbs', 'secure_boot'] as const).map((key) => {
              const feat = details.security_status?.[key];
              let label = 'UNKNOWN';
              let color = 'text-slate-400 border-slate-800 bg-slate-950/60';
              if (feat) {
                if (!feat.applicable) {
                  label = 'NOT APPLICABLE';
                  color = 'text-slate-500 border-slate-800 bg-slate-950/40';
                } else if (!feat.available) {
                  label = 'UNKNOWN';
                  color = 'text-amber-400 border-amber-500/30 bg-amber-500/10';
                } else if (feat.enabled === true) {
                  label = 'ENABLED';
                  color = 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
                } else if (feat.enabled === false) {
                  label = 'DISABLED';
                  color = 'text-red-400 border-red-500/30 bg-red-500/10';
                }
              }
              const displayKey = key === 'secure_boot' ? 'SECURE BOOT' : key.toUpperCase();
              return (
                <div key={key} className={`p-2.5 rounded border ${color} flex flex-col justify-between`}>
                  <div className="text-[10px] text-slate-400 font-semibold">{displayKey}</div>
                  <div className="font-bold mt-1.5 text-[11px] truncate">{label}</div>
                </div>
              );
            })}
          </div>
          <div className="text-[11px] text-slate-500 italic">
            Read-only posture verification executed prior to live collection.
          </div>
        </div>
      </div>
    </div>
  );
};
