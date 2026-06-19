"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  AnalystValidatedAction,
  AutomatedAction,
  ComplianceDocumentation,
  InvestigationReport,
  PivotTimelineEntry,
  RemediationPlaybook,
  SEVERITY_LABEL,
  Severity,
  TriageAssessment,
  api,
} from "@/lib/api";

const SEV_COLOR: Record<Severity, string> = {
  0: "bg-slate-600",
  1: "bg-sky-600",
  2: "bg-amber-600",
  3: "bg-orange-600",
  4: "bg-red-600",
};

const PRIORITY_COLOR: Record<string, string> = {
  IMMEDIATE: "bg-red-600",
  HIGH: "bg-orange-600",
  MEDIUM: "bg-amber-600",
  LOW: "bg-slate-600",
};

const FINDING_COLOR: Record<string, string> = {
  Satisfied: "bg-emerald-700 text-emerald-100",
  "Partially Satisfied": "bg-amber-700 text-amber-100",
  "Not Satisfied": "bg-red-700 text-red-100",
};

type Tab = "triage" | "timeline" | "playbook" | "compliance";

function AlertSelector({
  alerts,
  selectedId,
  onSelect,
  onInvestigate,
  loading,
}: {
  alerts: Alert[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onInvestigate: () => void;
  loading: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 p-4 text-sm font-medium text-slate-300">
        Alerts ({alerts.length})
      </div>
      <div className="max-h-[60vh] overflow-auto">
        {alerts.length === 0 && (
          <div className="p-3 text-xs text-slate-500">
            No alerts — inject a scenario from the dashboard.
          </div>
        )}
        {alerts.map((a) => {
          const selected = a.alert_id === selectedId;
          return (
            <div
              key={a.alert_id}
              onClick={() => onSelect(a.alert_id)}
              className={`cursor-pointer border-t border-slate-800 px-3 py-2 text-xs ${
                selected ? "bg-violet-950/40" : "hover:bg-slate-800/50"
              }`}
            >
              <div className="flex items-center gap-2">
                <span
                  className={`rounded px-2 py-0.5 text-[10px] font-semibold ${SEV_COLOR[a.severity]}`}
                >
                  {SEVERITY_LABEL[a.severity]}
                </span>
                <span className="font-mono">{a.rule}</span>
              </div>
              <div className="mt-1 text-slate-400">{a.host}</div>
              {a.mitre_techniques && a.mitre_techniques.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {a.mitre_techniques.map((t) => (
                    <span
                      key={t}
                      className="font-mono text-[10px] bg-slate-700 rounded px-1"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="border-t border-slate-800 p-3">
        <button
          onClick={onInvestigate}
          disabled={!selectedId || loading}
          className="w-full rounded bg-violet-700 px-3 py-2 text-xs font-medium text-white hover:bg-violet-600 disabled:opacity-50"
        >
          {loading ? "Investigating…" : "Investigate with Tier-3 AI"}
        </button>
      </div>
    </div>
  );
}

function TabBar({ tab, setTab }: { tab: Tab; setTab: (t: Tab) => void }) {
  const tabs: { key: Tab; label: string }[] = [
    { key: "triage", label: "Triage" },
    { key: "timeline", label: "Timeline" },
    { key: "playbook", label: "Playbook" },
    { key: "compliance", label: "Compliance" },
  ];
  return (
    <div className="flex border-b border-slate-800 text-sm">
      {tabs.map((t) => (
        <button
          key={t.key}
          onClick={() => setTab(t.key)}
          className={`px-4 py-2 transition-colors ${
            tab === t.key
              ? "border-b-2 border-violet-500 text-white"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

function statusChipColor(status: string): string {
  const s = status.toLowerCase();
  if (s.includes("remediat")) return "bg-emerald-700 text-emerald-100";
  if (s.includes("contain")) return "bg-amber-700 text-amber-100";
  if (s.includes("active")) return "bg-red-700 text-red-100";
  return "bg-slate-700 text-slate-100";
}

function severityToEnum(sev: string): Severity {
  const upper = sev.toUpperCase();
  if (upper.includes("CRITICAL")) return 4;
  if (upper.includes("HIGH")) return 3;
  if (upper.includes("MEDIUM")) return 2;
  if (upper.includes("LOW")) return 1;
  return 0;
}

function TriagePanel({ triage }: { triage: TriageAssessment }) {
  const sevEnum = severityToEnum(triage.severity);
  return (
    <div className="space-y-4 p-4 text-xs">
      <div className="flex flex-wrap gap-2">
        <span
          className={`rounded px-2 py-0.5 text-[10px] font-semibold ${SEV_COLOR[sevEnum]}`}
        >
          {triage.severity}
        </span>
        <span
          className={`rounded px-2 py-0.5 text-[10px] font-semibold ${statusChipColor(triage.status)}`}
        >
          {triage.status}
        </span>
      </div>
      <div>
        <div className="mb-1 font-semibold text-slate-300">Threat objectives</div>
        <p className="leading-relaxed text-slate-400">{triage.threat_objectives}</p>
      </div>
      <div>
        <div className="mb-1 font-semibold text-slate-300">Compromised assets</div>
        {triage.compromised_assets.length === 0 ? (
          <p className="text-slate-500">None identified.</p>
        ) : (
          <ul className="list-disc list-inside space-y-0.5 text-slate-400">
            {triage.compromised_assets.map((a, i) => (
              <li key={i} className="font-mono">
                {a}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function TimelinePanel({ timeline }: { timeline: PivotTimelineEntry[] }) {
  return (
    <div className="overflow-auto p-4">
      <table className="w-full text-left font-mono text-xs">
        <thead className="text-slate-400">
          <tr>
            <th className="p-2">Timestamp</th>
            <th className="p-2">Source</th>
            <th className="p-2">Asset/Identity</th>
            <th className="p-2">Activity/Artifact</th>
            <th className="p-2">Pivot Point</th>
          </tr>
        </thead>
        <tbody>
          {timeline.length === 0 && (
            <tr>
              <td className="p-3 text-slate-500" colSpan={5}>
                No timeline entries.
              </td>
            </tr>
          )}
          {timeline.map((e, i) => (
            <tr key={i} className="border-t border-slate-800">
              <td className="p-2 text-slate-300">{e.timestamp}</td>
              <td className="p-2 text-emerald-400">{e.source_environment}</td>
              <td className="p-2 text-slate-300">{e.asset_or_identity}</td>
              <td className="p-2 text-slate-400">{e.activity_or_artifact}</td>
              <td className="p-2 text-violet-300">{e.correlation_pivot_point}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ConfidenceBar({ value, color }: { value: number; color: string }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className="h-1.5 w-full overflow-hidden rounded bg-slate-800">
      <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

function PlaybookPanel({ playbook }: { playbook: RemediationPlaybook }) {
  return (
    <div className="space-y-6 p-4 text-xs">
      <section>
        <h3 className="mb-2 text-sm font-semibold text-emerald-300">
          Automated Actions (≥90% confidence)
        </h3>
        <p className="mb-3 text-[11px] text-slate-500">Will execute via SOAR engine</p>
        {playbook.automated_actions.length === 0 ? (
          <p className="text-slate-500">No automated actions proposed.</p>
        ) : (
          <div className="space-y-3">
            {playbook.automated_actions.map((a: AutomatedAction, i) => (
              <div
                key={i}
                className="rounded border border-slate-800 bg-slate-900 p-3"
              >
                <div className="mb-1 flex items-center justify-between">
                  <span className="font-mono text-slate-200">{a.activity_name}</span>
                  <span className="text-[10px] text-slate-400">
                    {(a.confidence_score * 100).toFixed(0)}%
                  </span>
                </div>
                <ConfidenceBar value={a.confidence_score} color="bg-emerald-500" />
                <p className="mt-2 text-slate-400">{a.rationale}</p>
              </div>
            ))}
          </div>
        )}
      </section>

      <section>
        <h3 className="mb-2 text-sm font-semibold text-amber-300">
          Analyst-Validated Actions (&lt;90%)
        </h3>
        {playbook.analyst_validated_actions.length === 0 ? (
          <p className="text-slate-500">No analyst-validated actions proposed.</p>
        ) : (
          <div className="space-y-3">
            {playbook.analyst_validated_actions.map((a: AnalystValidatedAction, i) => {
              const color = PRIORITY_COLOR[a.priority.toUpperCase()] ?? "bg-slate-600";
              return (
                <div
                  key={i}
                  className="rounded border border-slate-800 bg-slate-900 p-3"
                >
                  <div className="mb-1 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-semibold ${color}`}
                      >
                        {a.priority}
                      </span>
                      <span className="font-mono text-slate-200">{a.action}</span>
                    </div>
                    <span className="text-[10px] text-slate-400">
                      {(a.confidence_score * 100).toFixed(0)}%
                    </span>
                  </div>
                  <ConfidenceBar value={a.confidence_score} color="bg-amber-500" />
                  <p className="mt-2 text-slate-400">{a.rationale}</p>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

function CompliancePanel({ doc }: { doc: ComplianceDocumentation }) {
  return (
    <div className="space-y-6 p-4 text-xs">
      <section>
        <h3 className="mb-2 text-sm font-semibold text-slate-200">
          NIST SP 800-61r3 — IR Phases
        </h3>
        <table className="w-full text-left text-xs">
          <thead className="text-slate-400">
            <tr>
              <th className="p-2">Phase</th>
              <th className="p-2">Activities</th>
              <th className="p-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {doc.nist_ir_phases.map((p, i) => (
              <tr key={i} className="border-t border-slate-800 align-top">
                <td className="p-2 font-semibold text-slate-300">{p.phase}</td>
                <td className="p-2 text-slate-400">
                  <ul className="list-disc list-inside space-y-0.5">
                    {p.activities.map((act, j) => (
                      <li key={j}>{act}</li>
                    ))}
                  </ul>
                </td>
                <td className="p-2 text-slate-300">{p.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h3 className="mb-2 text-sm font-semibold text-slate-200">
          CRI Profile v2.2 — Diagnostic Statements
        </h3>
        <div className="space-y-2">
          {doc.cri_profile_statements.map((s, i) => {
            const findingColor =
              FINDING_COLOR[s.finding] ?? "bg-slate-700 text-slate-100";
            return (
              <div
                key={i}
                className="rounded border border-slate-800 bg-slate-900 p-3"
              >
                <div className="mb-1 flex items-center justify-between">
                  <span className="font-mono text-violet-300">{s.control_id}</span>
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-semibold ${findingColor}`}
                  >
                    {s.finding}
                  </span>
                </div>
                <p className="text-slate-300">{s.description}</p>
                <p className="mt-1 text-slate-500">
                  <span className="font-semibold">Evidence:</span> {s.evidence}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <h3 className="mb-2 text-sm font-semibold text-slate-200">
          Policy Recommendation
        </h3>
        <div className="border-l-4 border-violet-500 pl-4 text-slate-300">
          {doc.policy_update_recommendation}
        </div>
      </section>
    </div>
  );
}

export default function InvestigationView() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("triage");

  const refresh = useCallback(async () => {
    try {
      const a = await api.alerts();
      setAlerts(a);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [refresh]);

  const handleInvestigate = async () => {
    if (!selectedAlertId) return;
    setLoading(true);
    setError(null);
    try {
      const r = await api.investigateAlert(selectedAlertId);
      setReport(r);
      setTab("triage");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const isMock = report?.triage_assessment.threat_objectives.startsWith("[MOCK]") ?? false;

  return (
    <div className="space-y-5">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Tier-3 Investigation</h1>
        <p className="text-xs text-slate-500">
          Multi-dataset correlation · MITRE ATT&amp;CK · NIST 800-61r3 · CRI v2.2
        </p>
      </header>

      {error && (
        <div className="rounded border border-red-800 bg-red-950/50 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div>
          <AlertSelector
            alerts={alerts}
            selectedId={selectedAlertId}
            onSelect={setSelectedAlertId}
            onInvestigate={handleInvestigate}
            loading={loading}
          />
        </div>

        <div className="lg:col-span-2 rounded-lg border border-slate-800 bg-slate-900">
          {!report && !loading && (
            <div className="p-8 text-center text-sm text-slate-500">
              Select an alert and click <span className="text-violet-300">Investigate with Tier-3 AI</span>.
            </div>
          )}
          {loading && (
            <div className="p-8 text-center text-sm text-slate-400 animate-pulse">
              Claude is reconstructing the attack path…
            </div>
          )}
          {report && (
            <>
              {isMock && (
                <div className="m-4 rounded border border-amber-800 bg-amber-950/40 px-3 py-2 text-xs text-amber-300">
                  Mock mode — set <code className="font-mono">ANTHROPIC_API_KEY</code> for real Tier-3 analysis
                </div>
              )}
              <TabBar tab={tab} setTab={setTab} />
              {tab === "triage" && <TriagePanel triage={report.triage_assessment} />}
              {tab === "timeline" && (
                <TimelinePanel timeline={report.pivot_correlation_timeline} />
              )}
              {tab === "playbook" && (
                <PlaybookPanel playbook={report.remediation_playbook} />
              )}
              {tab === "compliance" && (
                <CompliancePanel doc={report.compliance_and_audit_documentation} />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
