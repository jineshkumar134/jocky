import { useState, useEffect } from 'react';
import { api } from './api';
import {
  CaseDetails,
  HostItem,
  EvidenceResponse,
  GraphData,
  TimelineData,
  RiskData,
  BlockchainVaspResponse,
  AnchoringResponse,
  ResearchResultItem,
} from './types';
import { CaseOverview } from './components/CaseOverview';
import { HostView } from './components/HostView';
import { EvidenceExplorer } from './components/EvidenceExplorer';
import { InvestigationGraph } from './components/InvestigationGraph';
import { InvestigationTimelineView } from './components/InvestigationTimelineView';
import { RiskAssessmentView } from './components/RiskAssessmentView';
import { BlockchainVaspView } from './components/BlockchainVaspView';
import { EvidenceAnchoringView } from './components/EvidenceAnchoringView';
import { SecurityResearchView } from './components/SecurityResearchView';
import {
  Shield,
  LayoutDashboard,
  Server,
  FileText,
  Share2,
  Clock,
  Link2,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  FlaskConical,
} from 'lucide-react';

const CASE_ID = 'JOCKY-FINAL-2026';

export function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Loaded Data State
  const [caseDetails, setCaseDetails] = useState<CaseDetails | null>(null);
  const [hosts, setHosts] = useState<HostItem[]>([]);
  const [evidenceData, setEvidenceData] = useState<EvidenceResponse | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [timelineData, setTimelineData] = useState<TimelineData | null>(null);
  const [riskData, setRiskData] = useState<RiskData | null>(null);
  const [blockchainData, setBlockchainData] = useState<BlockchainVaspResponse | null>(null);
  const [anchoringData, setAnchoringData] = useState<AnchoringResponse | null>(null);
  const [researchResults, setResearchResults] = useState<ResearchResultItem[]>([]);

  const loadInvestigationData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [details, hostList, evidence, graph, timeline, risk, bc, anchor, research] = await Promise.all([
        api.getCaseDetails(CASE_ID),
        api.getCaseHosts(CASE_ID),
        api.getCaseEvidence(CASE_ID),
        api.getCaseGraph(CASE_ID),
        api.getCaseTimeline(CASE_ID),
        api.getCaseRisk(CASE_ID),
        api.getCaseBlockchain(CASE_ID),
        api.getCaseAnchoring(CASE_ID),
        api.getCaseResearch(CASE_ID),
      ]);

      setCaseDetails(details);
      setHosts(hostList);
      setEvidenceData(evidence);
      setGraphData(graph);
      setTimelineData(timeline);
      setRiskData(risk);
      setBlockchainData(bc);
      setAnchoringData(anchor);
      setResearchResults(research);
    } catch (err: any) {
      setError(err.message || 'Failed to load investigation data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInvestigationData();
  }, []);

  const navItems = [
    { id: 'overview', label: 'Case Overview', icon: LayoutDashboard },
    { id: 'hosts', label: 'Hosts', icon: Server, badge: hosts.length },
    { id: 'evidence', label: 'Evidence', icon: FileText, badge: evidenceData?.evidence.length },
    { id: 'graph', label: 'Attack Graph', icon: Share2 },
    { id: 'timeline', label: 'Timeline', icon: Clock, badge: timelineData?.events.length },
    { id: 'risk', label: 'Risk Assessment', icon: Shield },
    { id: 'blockchain', label: 'Blockchain & VASP', icon: Link2 },
    { id: 'anchoring', label: 'Integrity Anchor', icon: ShieldCheck },
    { id: 'research', label: 'Research Lab', icon: FlaskConical, badge: researchResults.length },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center font-black text-white text-base shadow-lg shadow-cyan-500/20">
            J
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold tracking-tight text-white font-mono">JOCKY</h1>
              <span className="px-1.5 py-0.2 rounded bg-purple-500/10 border border-purple-500/30 text-[10px] font-mono text-purple-400 font-semibold">
                PHASE 16
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">Cybersecurity &bull; Forensic &amp; Research Lab</p>
          </div>
        </div>

        {/* Global Case Header Pill */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 bg-slate-900 border border-slate-800/80 px-3 py-1.5 rounded-lg text-xs font-mono">
            <span className="text-slate-500 text-[11px]">ACTIVE CASE:</span>
            <span className="text-cyan-400 font-semibold">{CASE_ID}</span>
          </div>

          <button
            onClick={loadInvestigationData}
            disabled={loading}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 transition disabled:opacity-50"
            title="Reload Investigation Data"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </header>

      {/* Main Layout Container */}
      <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
        {/* Sidebar Navigation */}
        <aside className="w-full md:w-64 border-r border-slate-800/80 bg-slate-950/60 p-4 shrink-0 flex flex-row md:flex-col gap-1 overflow-x-auto md:overflow-visible">
          <div className="hidden md:block text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 py-2">
            INVESTIGATION SECTIONS
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition whitespace-nowrap md:whitespace-normal ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-800">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </aside>

        {/* Content Area */}
        <main className="flex-1 p-6 overflow-y-auto max-w-7xl">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-32 space-y-4">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
              <p className="font-mono text-sm text-slate-400">Loading investigation case telemetry...</p>
            </div>
          ) : error ? (
            <div className="p-8 rounded-xl border border-red-500/30 bg-red-950/20 text-center space-y-3 max-w-md mx-auto my-16">
              <AlertTriangle className="w-10 h-10 text-red-400 mx-auto" />
              <h3 className="font-bold text-slate-100 text-base">Unable to load investigation</h3>
              <p className="text-xs text-red-300/80 font-mono leading-relaxed">{error}</p>
              <button
                onClick={loadInvestigationData}
                className="mt-2 px-4 py-2 rounded-lg bg-red-500/20 text-red-300 border border-red-500/40 text-xs font-semibold hover:bg-red-500/30 transition"
              >
                Retry Request
              </button>
            </div>
          ) : (
            <>
              {activeTab === 'overview' && caseDetails && (
                <CaseOverview details={caseDetails} onSelectTab={setActiveTab} />
              )}
              {activeTab === 'hosts' && <HostView hosts={hosts} />}
              {activeTab === 'evidence' && evidenceData && (
                <EvidenceExplorer evidenceData={evidenceData} />
              )}
              {activeTab === 'graph' && graphData && (
                <InvestigationGraph graphData={graphData} />
              )}
              {activeTab === 'timeline' && timelineData && (
                <InvestigationTimelineView timelineData={timelineData} />
              )}
              {activeTab === 'risk' && riskData && (
                <RiskAssessmentView riskData={riskData} />
              )}
              {activeTab === 'blockchain' && blockchainData && (
                <BlockchainVaspView data={blockchainData} />
              )}
              {activeTab === 'anchoring' && anchoringData && (
                <EvidenceAnchoringView data={anchoringData} />
              )}
              {activeTab === 'research' && (
                <SecurityResearchView researchResults={researchResults} />
              )}
            </>
          )}
        </main>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 px-6 py-3 text-center text-xs text-slate-500 font-mono flex flex-col sm:flex-row justify-between items-center gap-2">
        <span>JOCKY Investigation Dashboard &bull; Read-Only Visualization &bull; Phase 16</span>
        <span className="text-[11px] text-slate-600">Safe Simulation &bull; Security Research Lab Enabled</span>
      </footer>
    </div>
  );
}

export default App;
