// app/alerts/page.tsx
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getAlerts } from "@/lib/api";

const severityColor: Record<string, string> = {
  low: "bg-risk-low",
  medium: "bg-risk-medium",
  high: "bg-risk-high",
  critical: "bg-risk-critical",
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [sortBy, setSortBy] = useState<"score" | "time">("score");

  useEffect(() => {
    getAlerts().then(setAlerts);
  }, []);

  const sorted = [...alerts].sort((a, b) =>
    sortBy === "score" ? b.score - a.score : 0
  );

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-800">Alerts</h1>
        <div className="flex gap-2">
          <button
            onClick={() => setSortBy("score")}
            className={`rounded px-3 py-1 text-sm ${
              sortBy === "score" ? "bg-blue-600 text-white" : "bg-white text-gray-600"
            }`}
          >
            Sort by risk
          </button>
          <button
            onClick={() => setSortBy("time")}
            className={`rounded px-3 py-1 text-sm ${
              sortBy === "time" ? "bg-blue-600 text-white" : "bg-white text-gray-600"
            }`}
          >
            Sort by recency
          </button>
        </div>
      </div>

      <div className="overflow-hidden rounded-lg bg-white shadow">
        <table className="w-full text-left">
          <thead className="bg-gray-50 text-sm text-gray-500">
            <tr>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Host</th>
              <th className="px-4 py-3">Risk Score</th>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((alert) => (
              <tr key={alert.id} className="border-t border-gray-100">
                <td className="px-4 py-3">
                  <span
                    className={`rounded px-2 py-1 text-xs font-medium text-white ${severityColor[alert.severity]}`}
                  >
                    {alert.severity}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-700">{alert.host}</td>
                <td className="px-4 py-3 font-semibold text-gray-800">{alert.score}</td>
                <td className="px-4 py-3 text-gray-500">{alert.time}</td>
                <td className="px-4 py-3">
                  <Link
                    href={`/alerts/${alert.id}`}
                    className="text-sm text-blue-600 hover:underline"
                  >
                    View →
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}