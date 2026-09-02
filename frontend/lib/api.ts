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
