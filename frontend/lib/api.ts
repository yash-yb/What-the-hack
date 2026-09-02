/**
 * Thin fetch wrapper for the FastAPI backend.
 * Response shapes follow docs/api/api-contracts.md.
 */

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

export type HealthResponse = Record<string, unknown>;

export type RiskLevel = "low" | "medium" | "high";

export interface AlertCard {
  id: string;
  status: string;
  severity: string;
  title: string;
  summary: string;
  risk_score: number;
  risk_level: RiskLevel;
  predicted_attack_type: string | null;
  confidence_score: number;
  forecast_window_start: string;
  forecast_window_end: string;
  target_host: { ip_address: string; hostname: string | null } | null;
  created_at: string;
}

export interface AlertListResponse {
  items: AlertCard[];
  next_cursor: string | null;
}

async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(init.headers as Record<string, string>) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers, cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} for ${path}`);
  }
  return (await response.json()) as T;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export async function getAlerts() {
  return [
    { id: 1, host: "10.0.0.5", severity: "high", score: 82, time: "2 min ago" },
    { id: 2, host: "10.0.0.9", severity: "medium", score: 45, time: "10 min ago" },
    { id: 3, host: "10.0.0.14", severity: "critical", score: 96, time: "1 min ago" },
    { id: 4, host: "10.0.0.22", severity: "low", score: 12, time: "30 min ago" },
  ];
}

export interface AuthUser {
  id: string;
  email: string;
  display_name: string;
  role: "admin" | "analyst" | "viewer";
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_at: string;
  user: AuthUser;
}

/** POST /auth/login. The backend identifies users by email; 401 on bad credentials, 429 when rate-limited. */
export function login(email: string, password: string): Promise<TokenResponse> {
  return request<TokenResponse>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
}

export function refresh(refreshToken: string): Promise<TokenResponse> {
  return request<TokenResponse>("/auth/refresh", { method: "POST", body: JSON.stringify({ refresh_token: refreshToken }) });
}

export function logout(token: string): Promise<void> {
  return fetch(`${API_BASE_URL}/auth/logout`, { method: "POST", headers: { Authorization: `Bearer ${token}` } }).then(() => undefined);
}

export function listAlerts(token: string): Promise<AlertListResponse> {
  return request<AlertListResponse>("/alerts", {}, token);
}

export interface TrafficWindow {
  id: string;
  traffic_source_id: string;
  window_start: string;
  window_end: string;
  window_seconds: number;
  flow_count: number;
  packet_count: number;
  byte_count: number;
}

export interface TrafficWindowListResponse {
  items: TrafficWindow[];
  next_cursor: string | null;
}

/** Windows are paginated: pass the previous page's next_cursor as `after` to continue. */
export function listWindows(token: string, trafficSourceId: string, after?: string | null, limit = 200): Promise<TrafficWindowListResponse> {
  const params = new URLSearchParams({ traffic_source_id: trafficSourceId, limit: String(limit) });
  if (after) params.set("after", after);
  return request<TrafficWindowListResponse>(`/windows?${params.toString()}`, {}, token);
}

export async function getDashboardSummary() {
  return {
    riskCounts: { low: 12, medium: 7, high: 3, critical: 1 },
    trafficTrend: [
      { time: "10:00", value: 20 },
      { time: "10:05", value: 25 },
      { time: "10:10", value: 22 },
      { time: "10:15", value: 40 },
      { time: "10:20", value: 65 },
      { time: "10:25", value: 90 },
    ],
    topHosts: [
      { host: "10.0.0.14", score: 96 },
      { host: "10.0.0.5", score: 82 },
      { host: "10.0.0.9", score: 45 },
    ],
  };
}

export async function getAlertDetail(id: string) {
  // Fake detail data — keyed by id for now
  const details: Record<string, any> = {
    "1": {
      id: 1,
      host: "10.0.0.5",
      severity: "high",
      score: 82,
      predictedAttack: "Brute-force login",
      forecastHorizon: "Next 10 minutes",
      confidence: 0.87,
      contributingFactors: [
        "Failed login burst increased 4.2x",
        "Unusual login time (03:00–04:00 local)",
        "Requests from 3 new source IPs",
      ],
      recommendedActions: [
        "Temporarily lock account after 5 failed attempts",
        "Flag source IPs for review",
      ],
      trafficBefore: [10, 12, 11, 14, 40, 65],
      trafficAfter: [65, 70, 68, 72, 75, 78],
    },
  };

  return details[id] ?? details["1"]; // fallback so every id shows something for now
}
