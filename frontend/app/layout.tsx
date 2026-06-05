import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Incidentaling — SOC Simulator",
  description: "Interactive SIEM/SOAR incident response simulator",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="flex min-h-screen">
          <aside className="w-56 shrink-0 border-r border-slate-800 bg-slate-900 p-4">
            <div className="mb-6 text-lg font-bold tracking-tight text-emerald-400">
              ⬢ Incidentaling
            </div>
            <nav className="flex flex-col gap-1 text-sm">
              <Link className="rounded px-3 py-2 hover:bg-slate-800" href="/">
                SOC Dashboard
              </Link>
              <Link className="rounded px-3 py-2 hover:bg-slate-800" href="/playbooks">
                Playbook Editor
              </Link>
            </nav>
            <p className="mt-8 text-xs leading-relaxed text-slate-500">
              SIEM · EDR · SOAR simulation. Inject an attack, watch the SIEM detect it,
              and let the SOAR engine contain it.
            </p>
          </aside>
          <main className="flex-1 overflow-auto p-6">{children}</main>
        </div>
      </body>
    </html>
  );
}
