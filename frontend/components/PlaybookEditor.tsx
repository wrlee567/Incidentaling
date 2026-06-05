"use client";

import { useCallback, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Edge,
  Node,
  ReactFlow,
  ReactFlowProvider,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

// Activities the backend orchestration engine knows how to execute.
const ACTIVITIES = [
  "isolate_endpoint",
  "terminate_malicious_processes",
  "block_c2",
  "block_ip",
  "segregate_critical_systems",
  "lock_account",
  "force_password_reset",
  "enforce_mfa",
  "review_exfiltration",
  "compute_time_to_contain",
];

// The ransomware playbook, pre-laid-out as a DAG (mirrors the backend definition).
const initialNodes: Node[] = [
  { id: "isolate", position: { x: 0, y: 120 }, data: { label: "isolate_endpoint" }, type: "default" },
  { id: "terminate", position: { x: 260, y: 0 }, data: { label: "terminate_malicious_processes" } },
  { id: "block_c2", position: { x: 260, y: 120 }, data: { label: "block_c2" } },
  { id: "segregate", position: { x: 260, y: 240 }, data: { label: "segregate_critical_systems" } },
  { id: "ttc", position: { x: 560, y: 120 }, data: { label: "compute_time_to_contain" } },
];

const initialEdges: Edge[] = [
  { id: "e1", source: "isolate", target: "terminate" },
  { id: "e2", source: "isolate", target: "block_c2" },
  { id: "e3", source: "isolate", target: "segregate" },
  { id: "e4", source: "terminate", target: "ttc" },
  { id: "e5", source: "block_c2", target: "ttc" },
  { id: "e6", source: "segregate", target: "ttc" },
];

function Inner() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [activity, setActivity] = useState(ACTIVITIES[0]);

  const onConnect = useCallback(
    (c: Connection) => setEdges((eds) => addEdge(c, eds)),
    [setEdges],
  );

  const addNode = () => {
    const id = `${activity}-${nodes.length}`;
    setNodes((ns) => [
      ...ns,
      { id, position: { x: 120, y: 360 + ns.length * 10 }, data: { label: activity } },
    ]);
  };

  // Serialize the canvas into the backend's WorkflowDefinition shape.
  const definition = useMemo(() => {
    const depsOf = (id: string) =>
      edges.filter((e) => e.target === id).map((e) => e.source);
    return {
      name: "custom_playbook",
      steps: nodes.map((n) => ({
        id: n.id,
        activity: String(n.data.label),
        params: {},
        depends_on: depsOf(n.id),
      })),
    };
  }, [nodes, edges]);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2 h-[520px] rounded-lg border border-slate-800 bg-slate-900">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          fitView
          colorMode="dark"
        >
          <Background />
          <Controls />
        </ReactFlow>
      </div>
      <div className="space-y-3">
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="mb-2 text-sm font-medium text-slate-300">Add activity node</div>
          <select
            value={activity}
            onChange={(e) => setActivity(e.target.value)}
            className="w-full rounded bg-slate-800 p-2 text-xs"
          >
            {ACTIVITIES.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <button
            onClick={addNode}
            className="mt-2 w-full rounded bg-emerald-600 py-1.5 text-sm font-medium hover:bg-emerald-500"
          >
            + Add node
          </button>
          <p className="mt-2 text-xs text-slate-500">
            Drag from a node&apos;s handle to another to create a dependency edge.
          </p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="mb-2 text-sm font-medium text-slate-300">
            Serialized WorkflowDefinition
          </div>
          <pre className="max-h-64 overflow-auto rounded bg-slate-950 p-2 text-[10px] leading-relaxed text-emerald-300">
            {JSON.stringify(definition, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

export default function PlaybookEditor() {
  return (
    <ReactFlowProvider>
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">Playbook Editor</h1>
        <p className="text-sm text-slate-400">
          Build SOAR containment workflows as a DAG. The serialized JSON maps directly to
          the backend orchestration engine&apos;s <code>WorkflowDefinition</code>.
        </p>
        <Inner />
      </div>
    </ReactFlowProvider>
  );
}
