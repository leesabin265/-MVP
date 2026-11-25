import { useState } from "react";
import { api, atLeast, errorText, fmtTime } from "../api";
import type { Ctx } from "../App";
import { Empty, useLoad } from "../ui";

type Exc = {
  id: number; rule_id: string; path: string; param: string; expires_at: string; expired: boolean; reason: string;
  active: boolean; created_by: string; created_at: string; source_request_id: string | null; published: boolean;
};

export default function Exceptions({ ctx }: { ctx: Ctx }) {
  const [all, setAll] = useState(false);
  const { data, error, reload } = useLoad(() => api.get<Exc[]>(`/exceptions?include_inactive=${all}`), [all]);
  const canEdit = atLeast(ctx.me.role, "OPERATOR");

  const deactivate = async (e: Exc) => {
    if (!confirm(`예외 #${e.id} (${e.rule_id} · ${e.path} · ${e.param})를 비활성화할까요? 발행해야 반영됩니다.`)) return;
    try {
      await api.del(`/exceptions/${e.id}`);
      reload();
      ctx.refreshChanges();
    } catch (ex) {
      ctx.toast(errorText(ex), "err");
    }
  };

  if (error) return <div className="error">{errorText(error)}</div>;
  const soon = (iso: string) => new Date(iso).getTime() - Date.now() < 7 * 86400_000;

  return (
    <div className="stack">
      <div className="row between">
        <h2>예외</h2>
        <label className="row small">
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> 비활성 포함
        </label>
      </div>
      <p className="muted small">예외는 탐지 로그에서 ‘오탐 처리’로 만듭니다. 룰 1개·경로·파라미터·만료일이 모두 필요하고 와일드카드는 쓸 수 없습니다.</p>
      <div className="card flush scroll-x">
        {!data?.length ? (
          <Empty>예외가 없습니다.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr><th>#</th><th>룰</th><th>경로</th><th>파라미터</th><th>만료</th><th>근거</th><th>등록</th><th>상태</th><th /></tr>
            </thead>
            <tbody>
              {data.map((e) => (
                <tr key={e.id} className={e.active && !e.expired ? "" : "dim"}>
                  <td className="num">{e.id}</td>
                  <td className="mono">{e.rule_id}</td>
                  <td className="mono">{e.path}</td>
                  <td className="mono">{e.param}</td>
                  <td className="nowrap">
                    {fmtTime(e.expires_at)} {e.active && !e.expired && soon(e.expires_at) && <span className="badge amber">7일 내</span>}
                  </td>
                  <td>
                    {e.source_request_id ? (
                      <button className="link mono small" onClick={() => ctx.openEvent(e.source_request_id!)}>
                        {e.source_request_id.slice(0, 8)}…
                      </button>
                    ) : null}{" "}
                    <span className="small">{e.reason}</span>
                  </td>
                  <td className="small">{e.created_by}<br />{fmtTime(e.created_at)}</td>
                  <td>
                    {!e.active ? <span className="badge gray">비활성</span> : e.expired ? <span className="badge gray">만료</span>
                      : e.published ? <span className="badge green">적용 중</span> : <span className="badge amber">미발행</span>}
                  </td>
                  <td>{canEdit && e.active && <button className="btn small" onClick={() => deactivate(e)}>비활성화</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
