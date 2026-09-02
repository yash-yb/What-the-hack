"use client";

import { useEffect, useState } from "react";
import { getHealth, type HealthResponse } from "@/lib/api";

type State = { status: "loading" } | { status: "ok"; data: HealthResponse } | { status: "error"; message: string };

export function SystemStatus() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    getHealth()
      .then((data) => setState({ status: "ok", data }))
      .catch((error: unknown) =>
        setState({ status: "error", message: error instanceof Error ? error.message : "Backend unreachable" }),
      );
  }, []);

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-6">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Backend</p>
      {state.status === "loading" && <p className="mt-2 text-sm text-slate-500">Checking…</p>}
      {state.status === "ok" && (
        <p className="mt-2 text-sm">
          <span className="font-semibold text-risk-low">Healthy</span>
          <span className="block text-slate-500">{JSON.stringify(state.data)}</span>
        </p>
      )}
      {state.status === "error" && (
        <p className="mt-2 text-sm">
          <span className="font-semibold text-risk-high">Unreachable</span>
          <span className="block text-slate-500">{state.message}</span>
        </p>
      )}
    </div>
  );
}
