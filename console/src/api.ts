export type Role = "VIEWER" | "OPERATOR" | "ADMIN";
export type Me = { login_id: string; role: Role; csrf_token: string };

export class ApiError extends Error {
  constructor(public status: number, public body: any) {
    super(typeof body?.error === "string" ? body.error : body?.detail?.error ?? `HTTP ${status}`);
  }
}

let csrf = "";
let onUnauthorized: () => void = () => {};

export function setCsrf(token: string) {
  csrf = token;
}
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  const res = await fetch(`/admin/api${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text };
  }
  if (res.status === 401 && !path.startsWith("/auth/login")) onUnauthorized();
  if (!res.ok) {
    const httpExc = data && data.error === undefined && data.detail && typeof data.detail === "object" && !Array.isArray(data.detail);
    throw new ApiError(res.status, httpExc ? data.detail : data);
  }
  return data as T;
}

export const api = {
  get: <T>(p: string) => call<T>("GET", p),
  post: <T>(p: string, b: unknown = {}) => call<T>("POST", p, b),
  patch: <T>(p: string, b: unknown) => call<T>("PATCH", p, b),
  del: <T>(p: string) => call<T>("DELETE", p),
};

export const atLeast = (role: Role | undefined, need: Role) =>
  !!role && { VIEWER: 1, OPERATOR: 2, ADMIN: 3 }[role] >= { VIEWER: 1, OPERATOR: 2, ADMIN: 3 }[need];

export const fmtPct = (v: number | null | undefined) => (v == null ? "—" : `${(v * 100).toFixed(2)}%`);
export const fmtTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString("ko-KR", { hour12: false }) : "—";

export function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    const b = e.body ?? {};
    const code = b.error ?? b.detail?.error;
    const detail = typeof b.detail === "string" ? b.detail : "";
    const map: Record<string, string> = {
      invalid_credentials: "아이디 또는 비밀번호가 틀렸습니다.",
      account_locked: "로그인 5회 실패로 15분간 잠겼습니다.",
      too_many_attempts: "이 IP에서 실패가 너무 많습니다. 잠시 후 다시 시도하세요.",
      csrf_failed: "보안 토큰이 만료되었습니다. 새로고침하세요.",
      forbidden: "권한이 없습니다.",
      ip_not_allowed: "허용되지 않은 IP입니다.",
      no_changes: "발행할 변경 사항이 없습니다.",
      regression_failed: "회귀 테스트를 통과하지 못해 발행하지 않았습니다.",
      invalid_rule: "룰이 올바르지 않습니다.",
      exception_exists: "같은 예외가 이미 있습니다.",
      expires_at_out_of_range: "만료일은 1~180일 사이여야 합니다.",
      rule_exists: "같은 ID의 룰이 이미 있습니다.",
    };
    return [map[code] ?? code ?? `HTTP ${e.status}`, detail].filter(Boolean).join(" — ");
  }
  return String(e);
}
