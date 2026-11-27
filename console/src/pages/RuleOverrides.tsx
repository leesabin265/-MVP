import { FormEvent, useState } from "react";
import { api, atLeast, errorText, fmtTime } from "../api";
import type { Ctx } from "../App";
import { Empty, ModeBadge, useLoad } from "../ui";

type Item = {
  id: number; path: string; param: string | null; prefix: boolean; rule_id: string; mode: string;
  global_mode: string; weight: number; description: string; reason: string; active: boolean;
  created_by: string; created_at: string; published: boolean;
};
type RuleLite = { id: string; mode: string; weight: number; description: string; enabled: boolean };

/** 경로별 룰 모드(경로별 룰 그룹). 경로·파라미터에서만 룰 하나를 탐지(DETECT) 또는 차단(BLOCK)으로 바꾼다. */
export default function RuleOverrides({ ctx }: { ctx: Ctx }) {
  const { data, error, reload } = useLoad(() => api.get<Item[]>("/rule-overrides"));
  const rules = useLoad(() => api.get<RuleLite[]>("/rules"));
  const isAdmin = atLeast(ctx.me.role, "ADMIN");
  const [f, setF] = useState({ path: "/api/qna/posts", param: "content", prefix: false, rule_id: "", mode: "DETECT", reason: "" });
  const [err, setErr] = useState("");
  const picked = rules.data?.find((r) => r.id === f.rule_id);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await api.post("/rule-overrides", { ...f, param: f.param.trim() || null });
      setF({ ...f, reason: "" });
      reload();
      ctx.refreshChanges();
      ctx.toast("저장했습니다. 회귀 테스트 후 발행해야 반영됩니다.");
    } catch (ex) {
      setErr(errorText(ex));
    }
  };

  const remove = async (o: Item) => {
    if (!confirm(`#${o.id} ${o.path}${o.param ? ` · ${o.param}` : ""} 의 ${o.rule_id} → ${o.mode} 설정을 비활성화할까요?`)) return;
    try {
      await api.del(`/rule-overrides/${o.id}`);
      reload();
      ctx.refreshChanges();
    } catch (ex) {
      ctx.toast(errorText(ex), "err");
    }
  };

  if (error) return <div className="error">{errorText(error)}</div>;

  return (
    <div className="stack">
      <h2>경로별 룰 모드</h2>
      <p className="muted small">
        특정 경로·파라미터에서만 룰 하나의 모드를 바꿉니다. <b>탐지</b>로 낮추면 그 룰은 이 경로에서 차단 점수에 들어가지 않고 기록만 되고,
        <b> 차단</b>으로 올리면 전역에서는 탐지만 하는 룰이 이 경로에서는 차단 점수에 들어갑니다. 점수(가중치)와 탐지 기준은 그대로라
        낮춘 룰도 계속 기록됩니다. 한 룰에 여러 설정이 겹치면 가장 구체적인 하나만 적용됩니다.
      </p>

      <div className="card flush scroll-x">
        {!data?.length ? (
          <Empty>경로별 룰 모드가 없습니다. 모든 경로에서 룰의 전역 모드를 씁니다.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr><th>#</th><th>경로</th><th>파라미터</th><th>룰</th><th>모드</th><th>사유</th><th>등록</th><th>상태</th><th /></tr>
            </thead>
            <tbody>
              {data.map((o) => (
                <tr key={o.id}>
                  <td className="num">{o.id}</td>
                  <td className="mono">{o.path}{o.prefix ? " (접두사)" : ""}</td>
                  <td className="mono">{o.param ?? "전체"}</td>
                  <td><span className="mono">{o.rule_id}</span> <span className="small muted">+{o.weight} {o.description}</span></td>
                  <td>
                    <ModeBadge mode={o.global_mode} /> → <ModeBadge mode={o.mode} />{" "}
                    <span className={o.mode === "DETECT" ? "badge amber" : "badge green"}>{o.mode === "DETECT" ? "완화" : "강화"}</span>
                  </td>
                  <td className="small">{o.reason}</td>
                  <td className="small">{o.created_by}<br />{fmtTime(o.created_at)}</td>
                  <td>{o.published ? <span className="badge green">적용 중</span> : <span className="badge amber">미발행</span>}</td>
                  <td>{isAdmin && <button className="btn small" onClick={() => remove(o)}>비활성화</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {isAdmin ? (
        <form className="card stack" onSubmit={add}>
          <h3>추가 (ADMIN)</h3>
          <div className="form-grid">
            <label>경로<input value={f.path} onChange={(e) => setF({ ...f, path: e.target.value })} required /></label>
            <label>파라미터 (비우면 경로 전체)<input value={f.param} onChange={(e) => setF({ ...f, param: e.target.value })} /></label>
            <label>룰
              <select value={f.rule_id} onChange={(e) => {
                const r = rules.data?.find((x) => x.id === e.target.value);
                setF({ ...f, rule_id: e.target.value, mode: r?.mode === "BLOCK" ? "DETECT" : "BLOCK" });
              }} required>
                <option value="">선택</option>
                {rules.data?.filter((r) => r.enabled).map((r) => (
                  <option key={r.id} value={r.id}>{r.id} ({r.mode === "BLOCK" ? "차단" : "탐지"}, +{r.weight}) {r.description}</option>
                ))}
              </select>
            </label>
            <label>이 경로에서의 모드
              <select value={f.mode} onChange={(e) => setF({ ...f, mode: e.target.value })}>
                <option value="DETECT" disabled={picked?.mode === "DETECT"}>탐지 (기록만, 완화)</option>
                <option value="BLOCK" disabled={picked?.mode === "BLOCK"}>차단 (강화)</option>
              </select>
            </label>
            <label className="row small"><input type="checkbox" checked={f.prefix} onChange={(e) => setF({ ...f, prefix: e.target.checked })} /> 이 경로로 시작하는 모든 경로(접두사)</label>
            <label className="span2">사유 (필수, 감사 기록에 남음)<input value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} minLength={5} required /></label>
          </div>
          {err && <div className="error">{err}</div>}
          <div className="row"><button className="btn primary">저장</button></div>
          <p className="small muted">
            측정 예: 게시판 본문(/api/qna/posts · content, 차단 임계값 8)에서 XSS-004를 차단으로 올리면, 이 경로에서 차단되지 않고 기록만 되던
            공격이 21건(7.55%) → 11건(3.96%)으로 줄고 기술 Q&A 차단 오탐은 0/40 그대로입니다.
          </p>
        </form>
      ) : (
        <p className="muted small">경로별 룰 모드 추가·삭제는 ADMIN만 할 수 있습니다.</p>
      )}
    </div>
  );
}
