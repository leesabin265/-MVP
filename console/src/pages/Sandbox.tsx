import { FormEvent, useState } from "react";
import { api, errorText } from "../api";
import type { Ctx } from "../App";
import { ActionBadge, Code, ModeBadge } from "../ui";

type Verdict = {
  action: string; risk_score: number; policy_version: number; threshold: number; detect_threshold: number; steps: { name: string; value: string }[];
  signals: string[]; candidates: string[]; elapsed_ms: number;
  matches: { rule_id: string; category: string; score: number; mode: string; excepted: boolean; overridden?: boolean; evidence: string }[];
};

const SAMPLES = [
  ["시나리오 A", "admin%2527%20OR%201%3D1--", "query", "/api/login", "username"],
  ["시나리오 B", "UNION SELECT 문법이 헷갈려요. SELECT name FROM users UNION SELECT email FROM admins", "json", "/api/qna/posts", "content"],
  ["전각 XSS", "＜script＞alert(1)＜/script＞", "json", "/api/qna/posts", "content"],
  ["정상 이름", "O'Brien", "form", "/api/users/search", "name"],
];

export default function Sandbox({ ctx }: { ctx: Ctx }) {
  const [f, setF] = useState({ value: SAMPLES[0][1], location: "query", path: "/api/login", param: "username", use: "draft" });
  const [v, setV] = useState<Verdict | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (e?: FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    try {
      setV(await api.post<Verdict>("/policy/test", f));
    } catch (ex) {
      ctx.toast(errorText(ex), "err");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <h2>샌드박스</h2>
      <p className="muted small">입력 하나를 넣어 정규화 단계와 점수를 확인합니다. 실제 트래픽에는 영향이 없습니다.</p>
      <form className="card stack" onSubmit={run}>
        <div className="row wrap">
          {SAMPLES.map(([label, value, location, path, param]) => (
            <button type="button" key={label} className="btn small" onClick={() => setF({ ...f, value, location, path, param })}>
              {label}
            </button>
          ))}
        </div>
        <textarea className="mono" rows={4} value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} aria-label="입력값" />
        <div className="form-grid">
          <label>위치
            <select value={f.location} onChange={(e) => setF({ ...f, location: e.target.value })}>
              {["query", "form", "json", "header", "cookie", "path", "multipart", "body"].map((l) => <option key={l}>{l}</option>)}
            </select>
          </label>
          <label>경로<input value={f.path} onChange={(e) => setF({ ...f, path: e.target.value })} /></label>
          <label>파라미터<input value={f.param} onChange={(e) => setF({ ...f, param: e.target.value })} /></label>
          <label>정책
            <select value={f.use} onChange={(e) => setF({ ...f, use: e.target.value })}>
              <option value="draft">작업본(미발행 포함)</option>
              <option value="active">발행본</option>
            </select>
          </label>
        </div>
        <div className="row">
          <button className="btn primary" disabled={busy}>검사</button>
        </div>
      </form>

      {v && (
        <section className="card stack">
          <div className="row">
            <ActionBadge action={v.action} /> <b>위험 점수 {v.risk_score}</b>
            <span className="muted small">차단 임계값 {v.threshold} · 탐지 임계값 {v.detect_threshold} · {v.elapsed_ms} ms</span>
          </div>
          <ol className="steps">
            {v.steps.map((s, i) => (
              <li key={i}>
                <span className="step-name">{s.name}</span>
                <Code>{s.value}</Code>
              </li>
            ))}
          </ol>
          <p className="small muted">우회 신호: {v.signals.join(", ") || "없음"} · 프리필터 후보: {v.candidates.join(", ") || "없음"}</p>
          <table className="table">
            <thead><tr><th>룰</th><th>분류</th><th>모드</th><th className="num">점수</th><th>근거</th></tr></thead>
            <tbody>
              {v.matches.map((m, i) => (
                <tr key={i} className={m.excepted ? "struck" : ""}>
                  <td className="mono">{m.rule_id}</td><td>{m.category}</td><td><ModeBadge mode={m.mode} />{m.overridden && <span className="badge gray" title="경로별 룰 모드로 바뀐 모드">경로 설정</span>}</td>
                  <td className="num">{m.excepted ? "예외" : `+${m.score}`}</td><td><Code>{m.evidence}</Code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
