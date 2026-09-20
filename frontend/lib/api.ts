/**
 * Thin fetch wrapper for the FastAPI backend.
 * Response shapes follow docs/api/api-contracts.md.
 */

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

export type HealthResponse = Record<string, unknown>;

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type AlertStatus = "open" | "acknowledged" | "investigating" | "resolved";

export interface FeatureContribution {
  feature: string;
  contribution: number;
  description?: string;
  value?: number;
}

export interface TargetHost {
  ip_address: string;
  hostname: string | null;
  entity_type: string | null;
}

export interface AlertCard {
  id: string;
  prediction_id: string;
  status: AlertStatus;
  severity: RiskLevel;
  title: string;
  summary: string;
  risk_score: number;
  risk_level: RiskLevel;
  predicted_attack_type: string | null;
  predicted_stage: string | null;
  confidence_score: number;
  is_fallback: boolean;
  is_uncertain: boolean;
  is_ood: boolean;
  forecast_window_start: string;
  forecast_window_end: string;
  target_host: TargetHost | null;
  created_at: string;
  resolved_at: string | null;
  recommended_actions: string[];
  top_feature_contributors: FeatureContribution[];
}

export interface AlertEvent {
  id: string;
  event_type: string;
  from_status: AlertStatus | null;
  to_status: AlertStatus | null;
  note: string | null;
  actor_user_id: string | null;
  created_at: string;
}

export interface AlertDetail extends AlertCard {
  events: AlertEvent[];
}

/** Transitions the API accepts, mirroring app/services/alerts.py. */
export const ALLOWED_TRANSITIONS: Record<AlertStatus, AlertStatus[]> = {
  open: ["acknowledged", "investigating", "resolved"],
  acknowledged: ["investigating", "resolved", "open"],
  investigating: ["resolved", "acknowledged"],
  resolved: ["investigating"],
};

export interface AlertListResponse {
  items: AlertCard[];
  next_cursor: string | null;
}

async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
  if (!(init.body instanceof FormData)) headers["Content-Type"] = "application/json";
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

function notifySessionChange() {
  if (typeof window !== "undefined") window.dispatchEvent(new Event("wth-session-changed"));
}

export function saveSession(session: TokenResponse) {
  localStorage.setItem("wth_session", JSON.stringify(session));
  notifySessionChange();
}
export function getSession(): TokenResponse | null { const raw = typeof window === "undefined" ? null : localStorage.getItem("wth_session"); try { return raw ? JSON.parse(raw) as TokenResponse : null; } catch { return null; } }
export function clearSession() {
  if (typeof window !== "undefined") {
    localStorage.removeItem("wth_session");
    notifySessionChange();
  }
}
export function isUnauthorized(error: unknown) { return error instanceof Error && error.message.startsWith("401 "); }

export function refresh(refreshToken: string): Promise<TokenResponse> {
  return request<TokenResponse>("/auth/refresh", { method: "POST", body: JSON.stringify({ refresh_token: refreshToken }) });
}

export function logout(token: string): Promise<void> {
  return fetch(`${API_BASE_URL}/auth/logout`, { method: "POST", headers: { Authorization: `Bearer ${token}` } }).then(() => undefined);
}

export interface AlertFilters {
  status?: AlertStatus;
  severity?: RiskLevel;
  limit?: number;
  before?: string | null;
}

export function listAlerts(token: string, filters: AlertFilters = {}): Promise<AlertListResponse> {
  const params = new URLSearchParams();
  if (filters.status) params.set("status", filters.status);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.limit) params.set("limit", String(filters.limit));
  if (filters.before) params.set("before", filters.before);
  const query = params.toString();
  return request<AlertListResponse>(`/alerts${query ? `?${query}` : ""}`, {}, token);
}

export function getAlertDetail(token: string, id: string): Promise<AlertDetail> {
  return request<AlertDetail>(`/alerts/${id}`, {}, token);
}

/** Acknowledge, investigate, resolve, or reopen. Rejected transitions return 409. */
export function updateAlertStatus(token: string, id: string, status: AlertStatus, note?: string): Promise<AlertDetail> {
  return request<AlertDetail>(`/alerts/${id}/status`, { method: "PATCH", body: JSON.stringify({ status, note: note || null }) }, token);
}

export function addAlertNote(token: string, id: string, note: string): Promise<AlertEvent> {
  return request<AlertEvent>(`/alerts/${id}/notes`, { method: "POST", body: JSON.stringify({ note }) }, token);
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

export interface Overview {
  traffic_source_id: string; window_count: number; model_ready: boolean;
  traffic: { timestamp: string; packets: number; bytes: number; flows: number }[];
  latest_features: Record<string, number> | null;
  latest_destinations: { destination_ip: string; destination_port: number | null; protocol: string; flows: number; packets: number; bytes: number }[];
}
export interface Forecast {
  observed_until: string;
  peak_risk_level: RiskLevel;
  peak_risk_stage: string | null;
  predicted_attack_type?: string;
  confidence_score: number;
  is_uncertain: boolean;
  is_ood: boolean;
  is_fallback: boolean;
  fallback_reason: string | null;
  model_name: string;
  model_version: string;
  window_count: number;
  ood_features?: { feature: string; z_score: number }[];
  attack_candidates?: { label: string; family: string; tactic: string; technique_id: string; technique: string }[];
  risk_timeline: { step: number; risk_score: number; stage: string | null; stage_confidence?: number }[];
  top_feature_contributors: FeatureContribution[];
  explanation_summary?: string;
  mitigation_recommendation?: string;
}

export function getOverview(token: string, sourceId: string): Promise<Overview> {
  return request<Overview>(`/analytics/overview?traffic_source_id=${encodeURIComponent(sourceId)}`, {}, token);
}

export function getForecast(token: string, sourceId: string): Promise<Forecast> {
  return request<Forecast>(`/analytics/forecast?traffic_source_id=${encodeURIComponent(sourceId)}`, {}, token);
}
export function saveForecast(token: string, sourceId: string): Promise<{alert_id: string; forecast: Forecast}> {
  return request(`/analytics/forecast?traffic_source_id=${encodeURIComponent(sourceId)}`, { method: "POST" }, token);
}
export interface IngestionJob { id: string; traffic_source_id: string; status: string; total_rows: number; accepted_rows: number; skipped_rows: number; error_message: string | null; }
export interface TrafficSource { id: string; name: string; source_type: "csv_replay" | "zeek_live"; description: string | null; is_active: boolean; created_at: string; updated_at: string; }
export function listTrafficSources(token: string): Promise<TrafficSource[]> {
  return request<TrafficSource[]>("/ingestion/sources", {}, token);
}
export function startReplay(token: string, file: File): Promise<IngestionJob> {
  const form = new FormData(); form.append("file", file);
  return request<IngestionJob>("/ingestion/upload", { method: "POST", body: form }, token);
}
export function getJobStatus(token: string, jobId: string): Promise<IngestionJob> {
  return request<IngestionJob>(`/ingestion/${jobId}/status`, {}, token);
}

// --- Admin ------------------------------------------------------------------

export interface SystemOverview {
  counts: Record<string, number>;
  alerts_by_status: Record<string, number>;
  fallback_predictions: number;
  users: { email: string; display_name: string; role: string; is_active: boolean; last_login_at: string | null }[];
  models: {
    name: string;
    version: string;
    feature_schema_version: string;
    artifact_uri: string;
    is_active: boolean;
    metrics: Record<string, unknown>;
    created_at: string;
  }[];
  configuration: {
    environment: string;
    traffic_window_seconds: number;
    forecast_steps: number;
    max_upload_size_mb: number;
    rate_limit_enabled: boolean;
    login_rate_limit_per_minute: number;
    upload_rate_limit_per_minute: number;
    checkpoint_configured: boolean;
    checkpoint_present: boolean;
    uses_default_jwt_secret: boolean;
  };
}

export interface AuditEntry {
  id: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  actor_email: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export function getSystemOverview(token: string): Promise<SystemOverview> {
  return request<SystemOverview>("/system/overview", {}, token);
}

export function getAuditTrail(token: string, limit = 25): Promise<{ items: AuditEntry[] }> {
  return request<{ items: AuditEntry[] }>(`/system/audit?limit=${limit}`, {}, token);
}
