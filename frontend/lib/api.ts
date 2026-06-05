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

export interface Alert {
  alert_id: string;
  rule: string;
  severity: Severity;
  host: string;
  user: string;
  source_ip: string;
  ts: number;
  detail: string;
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
};
