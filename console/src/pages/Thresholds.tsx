import { FormEvent, useState } from "react";
import { api, atLeast, errorText, fmtTime } from "../api";
import type { Ctx } from "../App";
import { Empty, useLoad } from "../ui";

type Item = {
  id: number; path: string; param: string | null; prefix: boolean; threshold: number; reason: string;
  active: boolean; created_by: string; created_at: string; published: boolean;
};
type Resp = { global_threshold: number; items: Item[] };

export default function Thresholds({ ctx }: { ctx: Ctx }) {
  const { data, error, reload } = useLoad(() => api.get<Resp>("/thresholds"));
  const isAdmin = atLeast(ctx.me.role, "ADMIN");
  const g = data?.global_threshold ?? 6;
  const [f, setF] = useState({ path: "/api/qna/posts", param: "content", prefix: false, threshold: 8, reason: "" });
  const [err, setErr] = useState("");

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await api.post("/thresholds", { ...f, param: f.param.trim() || null, threshold: Number(f.threshold) });
      setF({ ...f, reason: "" });
      reload();
      ctx.refreshChanges();
      ctx.toast("저장했습니다. 회귀 테스트 후 발행해야 반영됩니다.");
    } catch (ex) {
      setErr(errorText(ex));
    }
  };

  const remove = async (t: Item) => {
    if (!confirm(`#${t.id} ${t.path}${t.param ? ` · ${t.param}` : ""} 임계값 ${t.threshold}을 비활성화할까요?`)) return;
    try {
      await api.del(`/thresholds/${t.id}`);
      reload();
      ctx.refreshChanges();
    } catch (ex) {
      ctx.toast(errorText(ex), "err");
    }
  };

  if (error) return <div className="error">{errorText(error)}</div>;

  return (
    <div className="stack">
      <h2>경로별 차단 임계값</h2>
      <p className="muted small">
        전역 임계값 {g}. 여기서 바꾸는 것은 <b>차단</b> 기준뿐이고 탐지 기준은 {g} 그대로입니다. 차단 임계값을 올리면 그 사이 점수의 요청은
        통과시키되 DETECT_ONLY로 기록합니다. 공격 문법을 정상적으로 쓰는 기술 게시판 같은 경로에만 쓰세요. 올릴 수 있는 최대값은 {g + 4}입니다.
      </p>

      <div className="card flush scroll-x">
        {!data?.items.length ? (
          <Empty>경로별 임계값이 없습니다. 모든 경로에 전역 임계값 {g}을 씁니다.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr><th>#</th><th>경로</th><th>파라미터</th><th className="num">차단 임계값</th><th>사유</th><th>등록</th><th>상태</th><th /></tr>
            </thead>
            <tbody>
              {data.items.map((t) => (
                <tr key={t.id}>
                  <td className="num">{t.id}</td>
                  <td className="mono">{t.path}{t.prefix ? " (접두사)" : ""}</td>
                  <td className="mono">{t.param ?? "전체"}</td>
                  <td className="num">
                    {t.threshold} <span className={t.threshold > g ? "badge amber" : "badge green"}>{t.threshold > g ? `완화 +${t.threshold - g}` : t.threshold < g ? `강화 ${t.threshold - g}` : "동일"}</span>
                  </td>
                  <td className="small">{t.reason}</td>
                  <td className="small">{t.created_by}<br />{fmtTime(t.created_at)}</td>
                  <td>{t.published ? <span className="badge green">적용 중</span> : <span className="badge amber">미발행</span>}</td>
                  <td>{isAdmin && <button className="btn small" onClick={() => remove(t)}>비활성화</button>}</td>
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
            <label>차단 임계값 (3–{g + 4})
              <input type="number" min={3} max={g + 4} value={f.threshold} onChange={(e) => setF({ ...f, threshold: Number(e.target.value) })} />
            </label>
            <label className="row small"><input type="checkbox" checked={f.prefix} onChange={(e) => setF({ ...f, prefix: e.target.checked })} /> 이 경로로 시작하는 모든 경로(접두사)</label>
            <label className="span2">사유 (필수, 감사 기록에 남음)<input value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} minLength={5} required /></label>
          </div>
          {err && <div className="error">{err}</div>}
          <div className="row"><button className="btn primary">저장</button></div>
          <p className="small muted">
            측정 예: /api/qna/posts · content 를 8로 하면 기술 Q&A 차단 오탐 4/40 → 0/40, 이 경로 공격 차단율 98.2% → 92.5% (탐지율 100% 유지).
          </p>
        </form>
      ) : (
        <p className="muted small">임계값 추가·삭제는 ADMIN만 할 수 있습니다.</p>
      )}
    </div>
  );
}
