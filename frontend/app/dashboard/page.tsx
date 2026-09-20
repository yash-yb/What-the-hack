"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  Forecast,
  Overview,
  clearSession,
  getForecast,
  getOverview,
  getSession,
  isUnauthorized,
  saveForecast,
} from "@/lib/api";

const badge: Record<string, string> = {
  low: "bg-emerald-100 text-emerald-800",
  medium: "bg-amber-100 text-amber-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

const mitreStages = [
  { stage: "Reconnaissance", source: "PortScan / reconnaissance", color: "bg-sky-500" },
  { stage: "Initial Access", source: "FTP/SSH Patator, web brute force, Heartbleed", color: "bg-amber-500" },
  { stage: "Lateral Movement", source: "Infiltration", color: "bg-violet-500" },
  { stage: "Command & Control", source: "Botnet", color: "bg-fuchsia-500" },
  { stage: "Impact", source: "DoS / DDoS harmful-impact bucket", color: "bg-rose-500" },
];

const mitreAttacks = [
  ["PortScan", "T1046", "Network Service Scanning"], ["FTP_Patator", "T1110", "Brute Force"], ["SSH_Patator", "T1110", "Brute Force"],
  ["Web_BruteForce", "T1110", "Brute Force"], ["Web_XSS", "T1190", "Exploit Public-Facing Application"], ["Web_SqlInjection", "T1190", "Exploit Public-Facing Application"],
  ["Heartbleed", "T1190", "Exploit Public-Facing Application"], ["Infiltration", "T1021", "Remote Services"], ["Botnet", "T1071", "Application Layer Protocol"],
  ["DoS_Hulk", "T1499", "Endpoint Denial of Service"], ["DoS_GoldenEye", "T1499", "Endpoint Denial of Service"], ["DoS_Slowloris", "T1499", "Endpoint Denial of Service"],
  ["DoS_Slowhttptest", "T1499", "Endpoint Denial of Service"], ["DDoS_LOIC", "T1498", "Network Denial of Service"],
] as const;

const featureDetails: Record<string, { label: string; why: string }> = {
  flow_count: { label: "Connection volume", why: "An unusual number of separate network connections occurred in one minute." },
  packet_count: { label: "Packet volume", why: "The number of packets differed from the recent traffic pattern." },
  byte_count: { label: "Data volume", why: "The amount of transferred data differed from the recent traffic pattern." },
  unique_dst_ips: { label: "Destination diversity", why: "Connections reached an unusual number of different destination IP addresses." },
  unique_dst_ports: { label: "Destination-port diversity", why: "Connections touched an unusual number of ports; this can occur during service discovery or scanning." },
  dst_port_entropy: { label: "Port spread", why: "Traffic was distributed across ports more broadly than the recent baseline." },
  protocol_udp_ratio: { label: "UDP share", why: "The proportion of UDP traffic changed from the recent pattern." },
  protocol_tcp_ratio: { label: "TCP share", why: "The proportion of TCP traffic changed from the recent pattern." },
  syn_ratio: { label: "Connection-start requests", why: "A higher share of connections began with SYN packets." },
  syn_ack_ratio: { label: "Handshake imbalance", why: "Connection-start requests and acknowledgements were imbalanced." },
  failed_conn_ratio: { label: "Failed connections", why: "More connections ended without a normal handshake or were reset." },
  rst_ratio: { label: "Connection resets", why: "A larger share of traffic contained reset signals." },
  retry_rate: { label: "Repeated connection attempts", why: "The same source–destination–port combination was retried more often." },
  short_flow_ratio: { label: "Short-lived connections", why: "A larger share of flows lasted under 100 milliseconds." },
  packet_burst_score: { label: "Packet burst", why: "Packet volume was elevated compared with the preceding three minutes." },
  syn_burst_score: { label: "SYN burst", why: "Connection-start activity was elevated compared with the preceding three minutes." },
  delta_packet_rate: { label: "Packet-rate change", why: "Packet rate changed sharply compared with the prior minute." },
  delta_failed_conn_ratio: { label: "Failure-rate change", why: "The failed-connection rate changed sharply compared with the prior minute." },
  delta_unique_dst_ports: { label: "Port-diversity change", why: "The number of destination ports changed sharply compared with the prior minute." },
};

const mitreExplanation: Record<string, string> = {
  "Reconnaissance": "MITRE ATT&CK tactic alignment: reconnaissance-like network discovery behaviour. This is not proof of a specific ATT&CK technique.",
  "Initial Access": "MITRE ATT&CK tactic alignment: an initial-access / credential-attempt pattern. It is a coarse category, not a claim that credentials were compromised.",
  "Lateral Movement": "MITRE ATT&CK tactic alignment: movement between systems may be developing. Validate with endpoint and identity telemetry before acting.",
  "Command & Control": "MITRE ATT&CK tactic alignment: traffic resembles a possible command-and-control communication pattern. Validate the destination and process ownership.",
  "Impact": "MITRE ATT&CK tactic alignment: high-impact behaviour is forecast. It does not prove a denial-of-service attack; inspect the affected flows and endpoints.",
  "Benign": "The model's most likely coarse class is benign for this forecast window.",
};

function formatFeatureValue(feature: string, value: number | undefined) {
  if (value === undefined) return "value unavailable";
  if (feature.includes("ratio")) return `${Math.round(value * 100)}%`;
  if (feature.includes("entropy")) return `${value.toFixed(2)} bits`;
  if (feature.includes("rate")) return `${value.toFixed(2)} / sec`;
  if (feature.includes("bytes") || feature.includes("length")) return `${Math.round(value).toLocaleString()} bytes`;
  return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(2);
}

function Line({ values, color = "#6366f1" }: { values: number[]; color?: string }) {
  if (!values.length) return null;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = Math.max(max - min, 1);
  const points = values
    .map((value, index) => `${(index / Math.max(values.length - 1, 1)) * 100},${90 - ((value - min) / span) * 76}`)
    .join(" ");

  return (
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-52 w-full overflow-visible">
      <path d="M0 90 H100" stroke="#e2e8f0" strokeWidth="1" />
      <polyline points={points} fill="none" stroke={color} strokeWidth="2.5" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Chart({ values, color, format, startLabel, endLabel }: { values: number[]; color: string; format: (value: number) => string; startLabel: string; endLabel: string }) {
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const middle = min + (max - min) / 2;
  return <div className="mt-4 grid grid-cols-[auto_1fr] gap-3"><div className="flex h-52 flex-col justify-between pb-1 text-right text-[11px] tabular-nums text-slate-400"><span>{format(max)}</span><span>{format(middle)}</span><span>{format(min)}</span></div><div><Line values={values} color={color} /><div className="flex justify-between text-xs text-slate-400"><span>{startLabel}</span><span>{endLabel}</span></div></div></div>;
}

export default function DashboardPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [forecast, setForecast] = useState<Forecast | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const session = getSession();
  const sourceId = typeof window === "undefined" ? null : localStorage.getItem("wth_source_id");

  useEffect(() => {
    if (!session || !sourceId) return;
    getOverview(session.access_token, sourceId)
      .then(setOverview)
      .catch((requestError) => {
        if (isUnauthorized(requestError)) {
          clearSession();
          window.location.href = "/login";
          return;
        }
        setError(requestError.message);
      });
    getForecast(session.access_token, sourceId).then(setForecast).catch(() => undefined);
  }, [session?.access_token, sourceId]);

  async function saveAlert() {
    if (!session || !sourceId) return;
    setSaving(true);
    try {
      const saved = await saveForecast(session.access_token, sourceId);
      window.location.href = `/alerts/${saved.alert_id}`;
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Could not save forecast");
    } finally {
      setSaving(false);
    }
  }

  if (!session) return <Empty title="Sign in to view live traffic" detail="The dashboard uses your analyst session to read uploaded data." href="/login" action="Sign in" />;
  if (!sourceId) return <Empty title="No traffic source selected" detail="Upload a normalized traffic CSV to create a 60-second feature timeline." href="/upload" action="Upload traffic" />;
  if (error) return <div className="rounded-xl border border-red-200 bg-red-50 p-5 text-red-800">Dashboard unavailable: {error}</div>;
  if (!overview) return <p className="text-slate-500">Loading your traffic timeline…</p>;

  const traffic = overview.traffic.slice(-60);
  const peak = forecast?.risk_timeline.reduce((current, point) => current.risk_score > point.risk_score ? current : point);
  const stageTransitions = forecast?.risk_timeline.filter((point, index, timeline) => index === 0 || point.stage !== timeline[index - 1].stage) ?? [];
  const projectedStage = peak?.stage ?? forecast?.risk_timeline[0]?.stage ?? "Unknown";
  const latestTraffic = traffic.at(-1);
  const peakTraffic = traffic.reduce((largest, point) => Math.max(largest, point.packets), 0);

  return (
    <div className="space-y-6">
      <section className="flex flex-col justify-between gap-4 rounded-2xl bg-slate-950 p-7 text-white md:flex-row md:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[.18em] text-indigo-300">Live forecasting workspace</p>
          <h2 className="mt-2 text-3xl font-semibold">Network risk, before it becomes an incident.</h2>
          <p className="mt-2 max-w-2xl text-sm text-slate-300">Source {sourceId.slice(0, 8)} · 60-second behavioural windows · next 5 minutes</p>
        </div>
        <Link href="/upload" className="rounded-lg bg-white px-4 py-2 text-sm font-semibold text-slate-900">Upload new traffic</Link>
      </section>

      <section className="grid gap-4 md:grid-cols-4">
        <Card label="Feature windows" value={String(overview.window_count)} hint="60-second snapshots" />
        <Card label="Flows observed" value={String(traffic.reduce((sum, point) => sum + point.flows, 0))} hint="in displayed timeline" />
        <Card label="Forecast status" value={forecast ? "Ready" : overview.model_ready ? "Need 10 windows" : "Artifact offline"} hint={forecast ? "world model running" : "upload more traffic or mount artifact"} />
        <Card label="Peak forecast risk" value={peak ? `${Math.round(peak.risk_score * 100)}%` : "—"} hint={peak?.stage ?? "no forecast yet"} accent={forecast?.peak_risk_level} />
      </section>

      <section className="grid gap-6 lg:grid-cols-5">
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm lg:col-span-3">
          <div className="flex justify-between">
            <div><h3 className="font-semibold text-slate-900">Observed traffic volume</h3><p className="text-sm text-slate-500">Packets per 60-second window · latest {latestTraffic?.packets.toLocaleString() ?? "0"} · peak {peakTraffic.toLocaleString()}</p></div>
            <span className="text-sm text-slate-500">{traffic.length} windows</span>
          </div>
          <Chart values={traffic.map((point) => point.packets)} color="#6366f1" format={(value) => `${Math.round(value).toLocaleString()}`} startLabel={traffic[0] ? new Date(traffic[0].timestamp).toLocaleTimeString() : ""} endLabel="Now" />
        </div>
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm lg:col-span-2">
          <h3 className="font-semibold text-slate-900">Forecasted risk</h3><p className="mb-4 text-sm text-slate-500">Five-minute model projection</p>
          {forecast ? <><Chart values={forecast.risk_timeline.map((point) => point.risk_score * 100)} color="#ef4444" format={(value) => `${Math.round(value)}%`} startLabel="+1 min" endLabel="+5 min" /><div className="flex items-center justify-between"><span className={`rounded-full px-3 py-1 text-xs font-semibold ${badge[forecast.peak_risk_level]}`}>{forecast.peak_risk_level.toUpperCase()} · {Math.round((peak?.risk_score ?? 0) * 100)}%</span><button onClick={saveAlert} disabled={saving} className="rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">{saving ? "Saving…" : "Save as alert"}</button></div></> : <p className="rounded-lg bg-slate-50 p-4 text-sm text-slate-500">A forecast appears once the model artifact is available and at least 10 windows are built.</p>}
        </div>
      </section>

      {forecast && <section className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-900">Forecasted attack stage</h3>
          <p className="mt-1 text-sm text-slate-500">A coarse, MITRE-aligned progression category—not exact technique attribution.</p>
          <div className="mt-4 rounded-xl border border-indigo-100 bg-indigo-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-[.14em] text-indigo-600">Five-minute verdict</p>
            <p className="mt-1 text-2xl font-semibold text-slate-900">{projectedStage}</p>
            <p className="mt-1 text-sm text-slate-600">{stageTransitions.length === 1 ? "Sustained across all five forecast windows; no stage transition is predicted." : `${stageTransitions.length} stage changes are predicted across the five-minute projection.`}</p>
          </div>
          <div className="mt-4 space-y-3">{forecast.risk_timeline.map((point) => <div key={point.step} className="flex items-center gap-3 text-sm"><span className="w-14 text-slate-500">+{point.step} min</span><div className="h-2 flex-1 rounded-full bg-slate-100"><div className="h-2 rounded-full bg-indigo-500" style={{ width: `${point.risk_score * 100}%` }} /></div><span className="w-12 text-right font-medium text-slate-700">{Math.round(point.risk_score * 100)}%</span></div>)}</div>
          {stageTransitions.length > 1 && <p className="mt-4 border-t border-slate-100 pt-4 text-sm text-slate-600">Stage changes: {stageTransitions.map((point) => `+${point.step} min ${point.stage ?? "Unknown"}`).join(" → ")}</p>}
          {forecast.attack_candidates?.length ? <div className="mt-4 border-t border-slate-100 pt-4"><p className="text-xs font-semibold uppercase tracking-[.14em] text-slate-500">Compatible training labels — not confirmed techniques</p><div className="mt-2 flex flex-wrap gap-2">{forecast.attack_candidates.map((candidate) => <span key={candidate.label} title={`${candidate.tactic}: ${candidate.technique_id} ${candidate.technique}`} className="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-700">{candidate.label}</span>)}</div></div> : null}
        </div>
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-900">What influenced this forecast</h3>
          <p className="mt-1 text-sm text-slate-500">These are the model&apos;s strongest input signals, not proof that any one signal caused an attack.</p>
          <div className="mt-4 space-y-4">{forecast.top_feature_contributors.slice(0, 5).map((item) => <div key={item.feature}><div className="flex justify-between gap-3 text-sm"><span className="font-medium text-slate-800">{featureDetails[item.feature]?.label ?? item.feature.replaceAll("_", " ")}</span><span className="shrink-0 text-slate-500">{Math.round(item.contribution * 100)}% influence</span></div><p className="mt-1 text-xs leading-5 text-slate-500">Current value: {formatFeatureValue(item.feature, overview.latest_features?.[item.feature])}. {featureDetails[item.feature]?.why ?? "This behaviour differed from the learned traffic pattern."}</p><div className="mt-1.5 h-2 rounded-full bg-slate-100"><div className="h-2 rounded-full bg-indigo-500" style={{ width: `${Math.max(3, item.contribution * 100)}%` }} /></div></div>)}</div>
        </div>
      </section>}

      {forecast && <section className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-amber-200 bg-amber-50/50 p-6 shadow-sm"><p className="text-xs font-semibold uppercase tracking-[.16em] text-amber-700">Plain-language reading</p><h3 className="mt-1 text-xl font-semibold text-slate-900">Why {Math.round((peak?.risk_score ?? 0) * 100)}% risk?</h3><p className="mt-3 text-sm leading-6 text-slate-700">The model compares the latest ten one-minute traffic windows with patterns learned during training. The percentage is an <strong>attack-likeness risk score for the next five minutes</strong>, not a calibrated probability or proof that an attack has succeeded.</p><p className="mt-3 text-sm leading-6 text-slate-700">{mitreExplanation[projectedStage] ?? "The stage is a coarse MITRE-aligned category and needs analyst validation."}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm"><p className="text-xs font-semibold uppercase tracking-[.16em] text-indigo-600">Destination evidence</p><h3 className="mt-1 text-xl font-semibold text-slate-900">Where was the recent traffic going?</h3><p className="mt-2 text-sm leading-6 text-slate-500">These are the busiest destinations in the latest one-minute window. An IP address or port is evidence to investigate—not a statement that the destination is harmful.</p><div className="mt-4 space-y-2">{overview.latest_destinations.length ? overview.latest_destinations.map((destination) => <div key={`${destination.destination_ip}-${destination.destination_port}-${destination.protocol}`} className="flex items-center justify-between gap-3 rounded-lg bg-slate-50 p-3 text-sm"><div><p className="font-mono font-medium text-slate-800">{destination.destination_ip}{destination.destination_port ? `:${destination.destination_port}` : ""}</p><p className="text-xs text-slate-500">{destination.protocol} · {destination.flows} flows · {destination.packets.toLocaleString()} packets</p></div><span className="text-xs text-slate-500">{destination.bytes.toLocaleString()} B</span></div>) : <p className="rounded-lg bg-slate-50 p-3 text-sm text-slate-500">No destination metadata is available for this window.</p>}</div><p className="mt-4 text-xs leading-5 text-slate-500">Website names are not inferred from IP addresses. Enable DNS/TLS-SNI enrichment in a future sensor version to show a verified domain name; do not label an IP as a risky website from this model alone.</p></div>
      </section>}

      <section className="rounded-2xl border border-indigo-100 bg-indigo-50/60 p-6 shadow-sm">
        <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-end"><div><p className="text-xs font-semibold uppercase tracking-[.16em] text-indigo-600">Model reference</p><h3 className="mt-1 text-xl font-semibold text-slate-900">MITRE-aligned stage mapping</h3></div><p className="max-w-xl text-sm text-slate-600">The model forecasts a coarse attack-progression category from flow behaviour. Analysts must validate it with endpoint, identity, and packet evidence; it does not assert an exact ATT&amp;CK technique.</p></div>
        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">{mitreStages.map((item) => <div key={item.stage} className="rounded-xl border border-white bg-white p-4"><span className={`mb-3 block h-1.5 w-10 rounded-full ${item.color}`} /><h4 className="font-semibold text-slate-900">{item.stage}</h4><p className="mt-1 text-xs leading-5 text-slate-500">Training label: {item.source}</p></div>)}</div>
        <div className="mt-5 grid gap-2 md:grid-cols-2 xl:grid-cols-3">{mitreAttacks.map(([label, id, technique]) => <div key={label} className="rounded-lg border border-white bg-white px-3 py-2 text-xs"><span className="font-semibold text-slate-800">{label}</span><span className="ml-2 text-slate-500">{id} · {technique}</span></div>)}</div>
        <p className="mt-4 text-xs text-slate-500">The table is a label-to-ATT&amp;CK reference, not an attribution engine. Benign is the sixth model class; DoS/DDoS maps to Impact, never to data exfiltration.</p>
      </section>
    </div>
  );
}

function Card({ label, value, hint, accent }: { label: string; value: string; hint: string; accent?: string }) {
  return <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><p className="text-sm text-slate-500">{label}</p><p className={`mt-2 text-2xl font-semibold ${accent === "critical" ? "text-red-600" : "text-slate-900"}`}>{value}</p><p className="mt-1 text-xs text-slate-400">{hint}</p></div>;
}

function Empty({ title, detail, href, action }: { title: string; detail: string; href: string; action: string }) {
  return <section className="rounded-2xl border border-dashed border-slate-300 bg-white p-12 text-center"><h2 className="text-2xl font-semibold text-slate-900">{title}</h2><p className="mx-auto mt-2 max-w-lg text-slate-500">{detail}</p><Link href={href} className="mt-6 inline-block rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white">{action}</Link></section>;
}
