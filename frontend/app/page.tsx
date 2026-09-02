import { SystemStatus } from "@/components/SystemStatus";

export default function HomePage() {
  return (
    <div className="space-y-8">
      <section className="rounded-lg border border-slate-200 bg-white p-6">
        <h2 className="text-xl font-semibold">Early warning, not just detection</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          The system groups recent traffic into short windows, extracts behavioural features, and forecasts the
          risk of an attack in the next 1–5 minutes. Every alert comes with ranked, human-readable reasons and a
          recommended next step for the analyst.
        </p>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <SystemStatus />
        <div className="rounded-lg border border-dashed border-slate-300 p-6 text-sm text-slate-500">
          Risk timeline — pending <code>GET /api/v1/predictions</code>
        </div>
        <div className="rounded-lg border border-dashed border-slate-300 p-6 text-sm text-slate-500">
          Prioritised alerts — pending <code>GET /api/v1/alerts</code>
        </div>
      </section>
    </div>
  );
}
