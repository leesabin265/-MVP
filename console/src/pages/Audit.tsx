import { Fragment, useState } from "react";
import { api, errorText, fmtTime } from "../api";
import type { Ctx } from "../App";
import { Empty, useLoad } from "../ui";

type Entry = {
  id: number; ts: string; actor: string; action: string; target: string; before: unknown; after: unknown;
  reason: string; client_ip: string | null;
};

const ACTIONS = ["", "auth.login", "auth.login_failed", "auth.account_locked", "event.view", "event.false_positive",
  "rule.create", "rule.update", "rule.mode", "exception.create", "exception.deactivate", "threshold.create", "threshold.deactivate", "policy.publish",
  "policy.publish_rejected", "policy.rollback"];

export default function Audit(_: { ctx: Ctx }) {
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const { data, error } = useLoad(
    () => api.get<Entry[]>(`/audit?limit=200${action ? `&action=${encodeURIComponent(action)}` : ""}${actor ? `&actor=${encodeURIComponent(actor)}` : ""}`),
    [action, actor],
  );
  const [open, setOpen] = useState<number | null>(null);

  return (
    <div className="stack">
      <h2>감사 기록</h2>
      <div className="filters card">
        <select value={action} onChange={(e) => setAction(e.target.value)} aria-label="동작">
          {ACTIONS.map((a) => <option key={a} value={a}>{a || "전체 동작"}</option>)}
        </select>
        <input placeholder="수행자" value={actor} onChange={(e) => setActor(e.target.value)} className="short" />
      </div>
      {error ? <div className="error">{errorText(error)}</div> : null}
      <div className="card flush scroll-x">
        {!data?.length ? (
          <Empty>기록이 없습니다.</Empty>
        ) : (
          <table className="table hover">
            <thead><tr><th>시각</th><th>수행자</th><th>동작</th><th>대상</th><th>사유</th><th>IP</th></tr></thead>
            <tbody>
              {data.map((e) => (
                <Fragment key={e.id}>
                  <tr onClick={() => setOpen(open === e.id ? null : e.id)}>
                    <td className="nowrap">{fmtTime(e.ts)}</td>
                    <td>{e.actor}</td>
                    <td className="mono">{e.action}</td>
                    <td className="mono">{e.target}</td>
                    <td className="small">{e.reason}</td>
                    <td className="mono">{e.client_ip}</td>
                  </tr>
                  {open === e.id && (
                    <tr className="detail-row">
                      <td colSpan={6}>
                        <div className="grid2">
                          <pre className="code block">{JSON.stringify(e.before, null, 2) ?? "—"}</pre>
                          <pre className="code block">{JSON.stringify(e.after, null, 2) ?? "—"}</pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <p className="muted small">감사 기록은 추가만 가능합니다(DB 권한과 트리거로 수정·삭제 차단). 1년 이상 보관합니다.</p>
    </div>
  );
}
