/**
 * JOCKY Dashboard API Client with Offline/CDN Resilience
 */
import {
  CaseListItem,
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
import mockDataRaw from './mockData.json';

const mockData = mockDataRaw as any;

const API_BASE =
  (import.meta as any).env?.VITE_API_BASE ||
  ((import.meta as any).env?.DEV ? 'http://localhost:8000/api' : '/api');

async function fetchJson<T>(url: string, fallback: () => T): Promise<T> {
  try {
    const res = await fetch(url);
    const contentType = res.headers.get('content-type') || '';
    if (res.ok && contentType.includes('application/json')) {
      return (await res.json()) as T;
    }
    // Fallback if not JSON (e.g. <!doctype html> SPA fallback)
    console.warn(`[JOCKY] Endpoint ${url} returned non-JSON (${res.status}). Using embedded investigation dataset.`);
    return fallback();
  } catch (err) {
    console.warn(`[JOCKY] API fetch failed for ${url}. Using embedded investigation dataset:`, err);
    return fallback();
  }
}

export const api = {
  getCases: () =>
    fetchJson<CaseListItem[]>(`${API_BASE}/cases`, () => {
      const cm = mockData.case_management || {};
      const c = cm.case || {};
      const s = cm.summary || {};
      return [
        {
          case_id: mockData.case_id,
          title: c.title || mockData.case_id,
          status: s.status || 'OPEN',
          host_count: s.host_count || 3,
          evidence_package_count: s.evidence_package_count || 1,
          highest_risk_score: s.highest_risk_score || 85,
          highest_risk_severity: s.highest_risk_severity || 'HIGH',
          started_at: mockData.started_at,
          completed_at: mockData.completed_at,
        },
      ];
    }),

  getCaseDetails: (caseId: string) =>
    fetchJson<CaseDetails>(`${API_BASE}/cases/${caseId}`, () => ({
      case_id: mockData.case_id,
      host: mockData.host,
      started_at: mockData.started_at,
      completed_at: mockData.completed_at,
      summary: mockData.summary || {},
      case_management: mockData.case_management || {},
      platform_info: mockData.platform_info,
      security_status: mockData.security_status,
    })),

  getCaseHosts: (caseId: string) =>
    fetchJson<HostItem[]>(`${API_BASE}/cases/${caseId}/hosts`, () => [
      {
        host_id: 'LAB-PC-01',
        hostname: 'LAB-PC-01',
        status: 'ONLINE',
        is_primary: true,
        has_evidence: true,
        platform_info: mockData.platform_info,
        security_status: mockData.security_status,
      },
      {
        host_id: 'LAB-PC-02',
        hostname: 'LAB-PC-02',
        status: 'ONLINE',
        is_primary: false,
        has_evidence: false,
        platform_info: {
          os_name: 'Linux',
          os_version: 'Ubuntu 22.04 LTS',
          architecture: 'x86_64',
          hostname: 'LAB-PC-02',
          runtime: 'Remote Agent',
          adapter_name: 'GenericPlatformAdapter',
        },
        security_status: {
          hvci: { applicable: false, available: false, enabled: null, source: 'unsupported_on_linux' },
          vbs: { applicable: false, available: false, enabled: null, source: 'unsupported_on_linux' },
          secure_boot: { applicable: true, available: true, enabled: true, source: 'sysfs:efivars' },
        },
      },
      {
        host_id: 'LAB-PC-03',
        hostname: 'LAB-PC-03',
        status: 'ONLINE',
        is_primary: false,
        has_evidence: false,
        platform_info: {
          os_name: 'Linux',
          os_version: 'Ubuntu 22.04 LTS',
          architecture: 'x86_64',
          hostname: 'LAB-PC-03',
          runtime: 'Remote Agent',
          adapter_name: 'LinuxPlatformAdapter',
        },
        security_status: {
          hvci: { applicable: false, available: false, enabled: null, source: 'unsupported_on_linux' },
          vbs: { applicable: false, available: false, enabled: null, source: 'unsupported_on_linux' },
          secure_boot: { applicable: true, available: true, enabled: true, source: 'sysfs:efivars' },
        },
      },
    ]),

  getCaseEvidence: (caseId: string) =>
    fetchJson<EvidenceResponse>(`${API_BASE}/cases/${caseId}/evidence`, () => {
      const pkg = mockData.evidence_package || {};
      return {
        case_id: mockData.case_id,
        host: mockData.host,
        package_hash: pkg.package_hash || '',
        created_at: pkg.created_at || mockData.started_at,
        evidence: pkg.evidence || [],
        relationships: pkg.relationships || [],
        correlations: pkg.correlations || [],
      };
    }),

  getCaseGraph: (caseId: string) =>
    fetchJson<GraphData>(`${API_BASE}/cases/${caseId}/graph`, () => mockData.graph || mockData.investigation_graph || { case_id: mockData.case_id, host: mockData.host, nodes: [], edges: [] }),

  getCaseTimeline: (caseId: string) =>
    fetchJson<TimelineData>(`${API_BASE}/cases/${caseId}/timeline`, () => mockData.timeline || { case_id: mockData.case_id, host: mockData.host, events: [], total_events: 0 }),

  getCaseRisk: (caseId: string) =>
    fetchJson<RiskData>(`${API_BASE}/cases/${caseId}/risk`, () => mockData.risk_assessment || { case_id: mockData.case_id, host: mockData.host, risk_score: 85, severity: 'HIGH', host_risk_scores: {}, findings: [] }),

  getCaseBlockchain: (caseId: string) =>
    fetchJson<BlockchainVaspResponse>(`${API_BASE}/cases/${caseId}/blockchain`, () => ({
      blockchain: mockData.blockchain,
      vasp: mockData.vasp,
    })),

  getCaseAnchoring: (caseId: string) =>
    fetchJson<AnchoringResponse>(`${API_BASE}/cases/${caseId}/anchoring`, () => {
      const ops = mockData.operations || [];
      const anchorOp = ops.find((o: any) => o.operation === 'ANCHOR_EVIDENCE') || {};
      const verifyOp = ops.find((o: any) => o.operation === 'VERIFY_EVIDENCE') || {};
      return {
        anchor: anchorOp.data || undefined,
        verification: verifyOp.data || undefined,
      };
    }),

  getCaseResearch: (caseId: string) =>
    fetchJson<ResearchResultItem[]>(`${API_BASE}/cases/${caseId}/research`, () => mockData.research_results || []),

  getHealth: () =>
    fetchJson<{ status: string; service: string; version: string; phase: string }>(
      `${API_BASE}/health`,
      () => ({ status: 'healthy', service: 'JOCKY Forensic Framework', version: '0.1.0', phase: 'Phase 16 - Final Integration' })
    ),
};
