/**
 * JOCKY Investigation Dashboard — Strong TypeScript Definitions
 */

export type CaseStatus = 'OPEN' | 'IN_PROGRESS' | 'CLOSED';
export type HostStatus = 'ONLINE' | 'OFFLINE' | 'UNKNOWN';
export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface CaseSummary {
  case_id: string;
  status: CaseStatus;
  host_count: number;
  evidence_package_count: number;
  evidence_item_count: number;
  relationship_count: number;
  correlation_count: number;
  highest_risk_score: number;
  highest_risk_severity: string;
  blockchain_finding_count: number;
  vasp_finding_count: number;
  anchor_record_count: number;
  generated_at: string;
}

export interface CaseListItem {
  case_id: string;
  title: string;
  status: CaseStatus;
  host_count: number;
  evidence_package_count: number;
  highest_risk_score: number;
  highest_risk_severity: string;
  started_at: string;
  completed_at: string;
}

export interface PlatformInfo {
  os_name: string;
  os_version: string;
  architecture: string;
  hostname: string;
  runtime: string;
  adapter_name: string;
  details?: Record<string, any>;
}

export interface SecurityFeatureStatus {
  enabled: boolean | null;
  available: boolean;
  applicable: boolean;
  source?: string | null;
  reason?: string | null;
}

export interface SecurityStatus {
  hvci: SecurityFeatureStatus;
  vbs: SecurityFeatureStatus;
  secure_boot: SecurityFeatureStatus;
  platform?: string;
  evaluated_at?: string;
}

export interface CaseDetails {
  case_id: string;
  host: string;
  started_at: string;
  completed_at: string;
  summary: {
    total_operations: number;
    successful_operations: number;
    partial_operations: number;
    failed_operations: number;
    unimplemented_operations: number;
  };
  case_management: {
    case?: {
      case_id: string;
      title: string;
      description: string;
      status: CaseStatus;
      created_at: string;
      updated_at: string;
      hosts: string[];
      evidence_packages: string[];
      metadata: Record<string, any>;
    };
    case_hash?: string;
    summary: CaseSummary;
  };
  platform_info?: PlatformInfo;
  security_status?: SecurityStatus;
}

export interface HostItem {
  host_id: string;
  hostname: string;
  status: HostStatus;
  is_primary: boolean;
  has_evidence: boolean;
  platform_info?: PlatformInfo;
  security_status?: SecurityStatus;
}

export interface UniversalEvidence {
  id: string;
  type: string;
  source: string;
  timestamp?: string | null;
  confidence: number;
  entity: Record<string, any>;
  relationships: any[];
  provenance: {
    collector: string;
    adapter: string;
    source: string;
    collection_method?: string;
    collected_at?: string;
    host?: string;
    case_id?: string;
  };
  integrity: {
    algorithm: string;
    value: string;
  };
}

export interface RelationshipItem {
  id: string;
  type: string;
  source_id: string;
  target_id: string;
  timestamp?: string | null;
  confidence: number;
  supporting_evidence: string[];
  metadata?: Record<string, any>;
}

export interface CorrelationItem {
  id: string;
  correlation_type: string;
  source_evidence_ids: string[];
  target_evidence_ids: string[];
  relationship_type: string;
  confidence: number;
  score: number;
  explanation: string;
  rule_id: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

export interface EvidenceResponse {
  case_id: string;
  host: string;
  package_hash: string;
  created_at: string;
  evidence: UniversalEvidence[];
  relationships: RelationshipItem[];
  correlations: CorrelationItem[];
}

export interface GraphNode {
  id: string;
  label: string;
  node_type?: string;
  type?: string;
  domain?: string;
  risk_level?: string;
  is_external?: boolean;
  confidence?: number;
  evidence_id?: string;
  first_seen?: string;
  last_seen?: string;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source_id?: string;
  target_id?: string;
  source?: string;
  target?: string;
  relationship_type?: string;
  type?: string;
  label?: string;
  weight?: number;
  confidence: number;
  evidence_ids?: string[];
  relationship_id?: string;
  correlation_id?: string;
  is_cross_domain?: boolean;
  timestamp?: string;
  metadata?: Record<string, any>;
}

export interface GraphData {
  case_id: string;
  host: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata?: Record<string, any>;
}

export interface TimelineEvent {
  event_id: string;
  timestamp?: string | null;
  category: string;
  event_type: string;
  title: string;
  description: string;
  confidence: number;
  source: string;
  evidence_ids: string[];
  correlation_id?: string;
  metadata?: Record<string, any>;
}

export interface TimelineData {
  case_id: string;
  host: string;
  generated_at: string;
  events: TimelineEvent[];
  summary?: {
    total_events: number;
    timed_events: number;
    untimed_events: number;
    first_timestamp?: string;
    last_timestamp?: string;
    event_type_counts?: Record<string, number>;
  };
}

export interface RiskFinding {
  finding_id: string;
  rule_id: string;
  title: string;
  description?: string;
  explanation: string;
  severity: { value: string } | string;
  score: number;
  confidence: number;
  evidence_ids: string[];
  metadata?: Record<string, any>;
}

export interface RiskData {
  case_id: string;
  host: string;
  generated_at: string;
  score: number;
  severity: { value: string } | string;
  findings: RiskFinding[];
  summary?: Record<string, any>;
}

export interface BlockchainWallet {
  address: string;
  wallet_type: string;
  label?: string;
  confidence: number;
}

export interface BlockchainTransaction {
  tx_hash: string;
  from_address: string;
  to_address: string;
  amount: number | string;
  asset: string;
  timestamp: string;
}

export interface BlockchainHop {
  hop_number: number;
  from_wallet: string;
  to_wallet: string;
  tx_hash: string;
  amount: number | string;
  asset: string;
  timestamp: string;
}

export interface BlockchainTraceData {
  seed_address: string;
  chain: string;
  wallets: BlockchainWallet[];
  transactions: BlockchainTransaction[];
  hops: BlockchainHop[];
  summary?: Record<string, any>;
}

export interface VaspAttribution {
  vasp_id: string;
  name: string;
  score: number;
  confidence: number;
  reasons: string[];
  scoring_breakdown?: Record<string, any>;
}

export interface VaspData {
  target_wallet: string;
  attributions: VaspAttribution[];
  summary?: Record<string, any>;
}

export interface BlockchainVaspResponse {
  blockchain?: BlockchainTraceData;
  vasp?: VaspData;
}

export interface AnchorRecord {
  package_hash: string;
  ipfs_cid: string;
  chain_id: number;
  tx_hash: string;
  block_number: number;
  contract_address: string;
  anchored_at: string;
  metadata?: Record<string, any>;
}

export interface VerificationRecord {
  is_valid: boolean;
  package_hash_match: boolean;
  ipfs_match: boolean;
  evm_match: boolean;
  expected_package_hash: string;
  actual_package_hash: string;
  details?: Record<string, any>;
  errors: string[];
}

export interface AnchoringResponse {
  anchor?: AnchorRecord;
  verification?: VerificationRecord;
}

export interface ResearchFindingItem {
  finding_id: string;
  rule_id: string;
  severity: string;
  confidence: number;
  explanation: string;
  observable_ids: string[];
  simulated: boolean;
  metadata: Record<string, any>;
}

export interface ResearchObservableItem {
  observable_id: string;
  observable_type: string;
  timestamp: string;
  source: string;
  attributes: Record<string, any>;
  confidence: number;
  simulated: boolean;
}

export interface ResearchScenarioItem {
  scenario_id: string;
  name: string;
  category: string;
  description: string;
  safety_level: string;
  simulated: boolean;
  expected_observables: string[];
  metadata: Record<string, any>;
}

export interface ResearchBenchmarkItem {
  scenario_id: string;
  duration_ms: number;
  observable_count: number;
  detection_count: number;
  detection_coverage: number;
  metric_details: Record<string, any>;
}

export interface ResearchResultItem {
  scenario: ResearchScenarioItem;
  observables: ResearchObservableItem[];
  findings: ResearchFindingItem[];
  benchmark: ResearchBenchmarkItem;
  generated_at: string;
  result_hash: string;
}
