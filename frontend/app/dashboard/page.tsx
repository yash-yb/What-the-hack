// app/dashboard/page.tsx
"use client";

import { useEffect, useState } from "react";
import { getDashboardSummary } from "@/lib/api";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

export default function DashboardPage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    getDashboardSummary().then(setData);
  }, []);

  if (!data) return <p className="p-8">Loading dashboard...</p>;

  const { riskCounts, trafficTrend, topHosts } = data;

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <h1 className="mb-6 text-2xl font-bold text-gray-800">Dashboard</h1>

      {/* Risk summary cards */}
      <div className="mb-8 grid grid-cols-4 gap-4">
        <RiskCard label="Low" count={riskCounts.low} color="bg-risk-low" />
        <RiskCard label="Medium" count={riskCounts.medium} color="bg-risk-medium" />
        <RiskCard label="High" count={riskCounts.high} color="bg-risk-high" />
        <RiskCard label="Critical" count={riskCounts.critical} color="bg-risk-critical" />
      </div>

      {/* Traffic trend chart */}
      <div className="mb-8 rounded-lg bg-white p-6 shadow">
        <h2 className="mb-4 text-lg font-semibold text-gray-700">
          Traffic Trend
        </h2>
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={trafficTrend}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Line type="monotone" dataKey="value" stroke="#2563eb" strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Top suspicious hosts */}
      <div className="rounded-lg bg-white p-6 shadow">
        <h2 className="mb-4 text-lg font-semibold text-gray-700">
          Top Suspicious Hosts
        </h2>
        <ul>
          {topHosts.map((h: any) => (
            <li
              key={h.host}
              className="flex justify-between border-b border-gray-100 py-2 last:border-0"
            >
              <span className="text-gray-700">{h.host}</span>
              <span className="font-semibold text-risk-high">{h.score}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function RiskCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className={`rounded-lg p-4 text-white shadow ${color}`}>
      <p className="text-sm opacity-90">{label}</p>
      <p className="text-3xl font-bold">{count}</p>
    </div>
  );
}