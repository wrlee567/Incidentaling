"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  EnvironmentState,
  SEVERITY_LABEL,
  Severity,
  Stats,
  WorkflowRun,
  api,
} from "@/lib/api";

const SEV_COLOR: Record<Severity, string> = {
  0: "bg-slate-600",
  1: "bg-sky-600",
  2: "bg-amber-600",
  3: "bg-orange-600",
  4: "bg-red-600",
};

function StatCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {sub && <div className="text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

function Bars({ stats }: { stats: Stats }) {
  const max = Math.max(1, ...Object.values(stats).map((s) => s.rows));
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="mb-3 text-sm font-medium text-slate-300">Telemetry by source</div>
      <div className="space-y-2">
        {Object.entries(stats).map(([kind, s]) => (
          <div key={kind} className="flex items-center gap-2 text-xs">
            <span className="w-16 text-slate-400">{kind}</span>
            <div className="h-4 flex-1 overflow-hidden rounded bg-slate-800">
              <div
                className="h-full bg-emerald-500"
                style={{ width: `${(s.rows / max) * 100}%` }}
              />
            </div>
            <span className="w-10 text-right tabular-nums">{s.rows}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AlertsTable({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 p-4 text-sm font-medium text-slate-300">
        Alerts ({alerts.length})
      </div>
      <div className="max-h-80 overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-slate-900 text-slate-400">
            <tr>
              <th className="p-2">Severity</th>
              <th className="p-2">Rule</th>
              <th className="p-2">Host</th>
              <th className="p-2">Detail</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 && (
              <tr>
                <td className="p-3 text-slate-500" colSpan={4}>
                  No alerts yet — inject a scenario and run detection.
                </td>
              </tr>
            )}
            {alerts.map((a) => (
              <tr key={a.alert_id} className="border-t border-slate-800">
                <td className="p-2">
                  <span className={`rounded px-2 py-0.5 text-[10px] font-semibold ${SEV_COLOR[a.severity]}`}>
                    {SEVERITY_LABEL[a.severity]}
                  </span>
                </td>
                <td className="p-2 font-mono">{a.rule}</td>
                <td className="p-2">{a.host}</td>
                <td className="p-2 text-slate-400">{a.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EnvPanel({ env, runs }: { env: EnvironmentState | null; runs: WorkflowRun[] }) {
  const rows: [string, string[]][] = env
    ? [
        ["Isolated hosts", env.isolated_hosts],
        ["Blocked IPs", env.blocked_ips],
        ["Locked accounts", env.locked_accounts],
        ["MFA enforced", env.mfa_enforced],
        ["Segregated subnets", env.segregated_subnets],
      ]
    : [];
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="mb-3 text-sm font-medium text-slate-300">Containment state</div>
      <div className="space-y-1 text-xs">
        {rows.map(([label, items]) => (
          <div key={label} className="flex justify-between gap-2">
            <span className="text-slate-400">{label}</span>
            <span className="text-right font-mono text-emerald-300">
              {items.length ? items.join(", ") : "—"}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-4 border-t border-slate-800 pt-3 text-xs">
        <div className="mb-1 text-slate-400">Workflow runs</div>
        {runs.length === 0 && <div className="text-slate-500">none</div>}
        {runs.map((r) => (
          <div key={r.run_id} className="flex justify-between">
            <span className="font-mono">{r.name}</span>
            <span className={r.status === "COMPLETED" ? "text-emerald-400" : "text-amber-400"}>
              {r.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({});
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [env, setEnv] = useState<EnvironmentState | null>(null);
  const [runs, setRuns] = useState<WorkflowRun[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, a, e, r] = await Promise.all([
        api.stats(),
        api.alerts(),
        api.environment(),
        api.runs(),
      ]);
      setStats(s);
      setAlerts(a);
      setEnv(e);
      setRuns(r);
      setError(null);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [refresh]);

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label);
    try {
      await fn();
      await refresh();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const totalRows = Object.values(stats).reduce((n, s) => n + s.rows, 0);
  const totalBytes = Object.values(stats).reduce((n, s) => n + s.bytes, 0);

  return (
    <div className="space-y-5">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">SOC Dashboard</h1>
        <div className="flex flex-wrap gap-2 text-sm">
          <button
            onClick={() => act("brute", () => api.simulate("brute_force"))}
            disabled={!!busy}
            className="rounded bg-amber-600 px-3 py-1.5 font-medium hover:bg-amber-500 disabled:opacity-50"
          >
            Inject brute-force
          </button>
          <button
            onClick={() => act("ransom", () => api.simulate("ransomware"))}
            disabled={!!busy}
            className="rounded bg-red-600 px-3 py-1.5 font-medium hover:bg-red-500 disabled:opacity-50"
          >
            Inject ransomware
          </button>
          <button
            onClick={() => act("detect", () => api.detect())}
            disabled={!!busy}
            className="rounded bg-sky-600 px-3 py-1.5 font-medium hover:bg-sky-500 disabled:opacity-50"
          >
            Run detection
          </button>
          <button
            onClick={() => act("respond", () => api.respond())}
            disabled={!!busy}
            className="rounded bg-emerald-600 px-3 py-1.5 font-medium hover:bg-emerald-500 disabled:opacity-50"
          >
            SOAR respond
          </button>
        </div>
      </header>

      {error && (
        <div className="rounded border border-red-800 bg-red-950/50 p-3 text-sm text-red-300">
          {error} — is the backend running on {process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000"}?
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Events stored" value={totalRows.toLocaleString()} />
        <StatCard label="Storage" value={`${(totalBytes / 1024).toFixed(1)} KB`} sub="precision-typed columns" />
        <StatCard label="Alerts" value={String(alerts.length)} />
        <StatCard label="Workflows" value={String(runs.length)} sub="SOAR runs" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          <Bars stats={stats} />
          <AlertsTable alerts={alerts} />
        </div>
        <EnvPanel env={env} runs={runs} />
      </div>
    </div>
  );
}
