// Typed client for the Incidentaling backend.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

export type Severity = 0 | 1 | 2 | 3 | 4;
export const SEVERITY_LABEL: Record<Severity, string> = {
  0: "INFO",
  1: "LOW",
  2: "MEDIUM",
  3: "HIGH",
  4: "CRITICAL",
};

export interface AlertEnrichment {
  alert_id: string;
  explanation: string;
  severity_justification: string;
  recommended_actions: string[];
  threat_intel: string;
  confidence: number;
}

export interface Alert {
  alert_id: string;
  rule: string;
  severity: Severity;
  host: string;
  user: string;
  source_ip: string;
  ts: number;
  detail: string;
  // AI enrichment fields — populated asynchronously after detection
  ai_explanation?: string | null;
  ai_severity_justification?: string | null;
  ai_recommended_actions?: string[] | null;
  ai_threat_intel?: string | null;
  mitre_techniques?: string[];
}

// -- Tier-3 investigation types ---------------------------------------------

export interface TriageAssessment {
  threat_objectives: string;
  severity: string;
  status: string;
  compromised_assets: string[];
}

export interface PivotTimelineEntry {
  timestamp: string;
  source_environment: string;
  asset_or_identity: string;
  activity_or_artifact: string;
  correlation_pivot_point: string;
}

export interface AutomatedAction {
  action: string;
  activity_name: string;
  params: Record<string, unknown>;
  confidence_score: number;
  rationale: string;
}

export interface AnalystValidatedAction {
  action: string;
  priority: string;
  confidence_score: number;
  rationale: string;
}

export interface RemediationPlaybook {
  automated_actions: AutomatedAction[];
  analyst_validated_actions: AnalystValidatedAction[];
}

export interface NistIrPhase {
  phase: string;
  activities: string[];
  status: string;
}

export interface CriDiagnosticStatement {
  control_id: string;
  description: string;
  finding: string;
  evidence: string;
}

export interface ComplianceDocumentation {
  nist_ir_phases: NistIrPhase[];
  cri_profile_statements: CriDiagnosticStatement[];
  policy_update_recommendation: string;
}

export interface InvestigationReport {
  alert_id: string;
  triage_assessment: TriageAssessment;
  pivot_correlation_timeline: PivotTimelineEntry[];
  remediation_playbook: RemediationPlaybook;
  compliance_and_audit_documentation: ComplianceDocumentation;
}

export interface TableStats {
  rows: number;
  partitions: number;
  bytes: number;
}

export type Stats = Record<string, TableStats>;

export interface EnvironmentState {
  isolated_hosts: string[];
  terminated_on: string[];
  blocked_ips: string[];
  segregated_subnets: string[];
  locked_accounts: string[];
  password_resets: string[];
  mfa_enforced: string[];
  exfil_reviews: Record<string, string>;
  actions: string[];
}

export interface WorkflowRun {
  run_id: string;
  name: string;
  status: string;
  created_ts: number;
  updated_ts: number;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} on ${path}`);
  return res.json() as Promise<T>;
}

export const api = {
  stats: () => req<Stats>("/query/stats"),
  alerts: () => req<Alert[]>("/query/alerts"),
  environment: () => req<EnvironmentState>("/soar/environment"),
  runs: () => req<WorkflowRun[]>("/soar/runs"),
  simulate: (scenario: string, difficulty = 2) =>
    req<{ scenario: string; injected: number }>(
      `/simulate?scenario=${scenario}&difficulty=${difficulty}`,
      { method: "POST" },
    ),
  detect: () => req<{ new_alerts: Alert[] }>("/detect", { method: "POST" }),
  respond: () =>
    req<{ launched: unknown[] }>("/soar/respond", { method: "POST" }),
  enrichAlert: (alertId: string) =>
    req<AlertEnrichment>("/ai/enrich", {
      method: "POST",
      body: JSON.stringify({ alert_id: alertId }),
    }),
  investigateAlert: (alertId: string) =>
    req<InvestigationReport>("/ai/investigate", {
      method: "POST",
      body: JSON.stringify({ alert_id: alertId }),
    }),
};
