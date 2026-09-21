/**
 * JOCKY Dashboard API Client
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

const API_BASE =
  (import.meta as any).env?.VITE_API_BASE ||
  ((import.meta as any).env?.DEV ? 'http://localhost:8000/api' : '/api');

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    let errorMsg = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const err = await res.json();
      if (err.detail) errorMsg = err.detail;
    } catch {
      // fallback to status text
    }
    throw new Error(errorMsg);
  }
  return res.json() as Promise<T>;
}

export const api = {
  getCases: () => fetchJson<CaseListItem[]>(`${API_BASE}/cases`),
  getCaseDetails: (caseId: string) => fetchJson<CaseDetails>(`${API_BASE}/cases/${caseId}`),
  getCaseHosts: (caseId: string) => fetchJson<HostItem[]>(`${API_BASE}/cases/${caseId}/hosts`),
  getCaseEvidence: (caseId: string) => fetchJson<EvidenceResponse>(`${API_BASE}/cases/${caseId}/evidence`),
  getCaseGraph: (caseId: string) => fetchJson<GraphData>(`${API_BASE}/cases/${caseId}/graph`),
  getCaseTimeline: (caseId: string) => fetchJson<TimelineData>(`${API_BASE}/cases/${caseId}/timeline`),
  getCaseRisk: (caseId: string) => fetchJson<RiskData>(`${API_BASE}/cases/${caseId}/risk`),
  getCaseBlockchain: (caseId: string) => fetchJson<BlockchainVaspResponse>(`${API_BASE}/cases/${caseId}/blockchain`),
  getCaseAnchoring: (caseId: string) => fetchJson<AnchoringResponse>(`${API_BASE}/cases/${caseId}/anchoring`),
  getCaseResearch: (caseId: string) => fetchJson<ResearchResultItem[]>(`${API_BASE}/cases/${caseId}/research`),
  getHealth: () => fetchJson<{ status: string; service: string; version: string; phase: string }>(`${API_BASE}/health`),
};
