import { useState } from "react";
import { api, ApiError, atLeast, errorText, fmtPct, fmtTime } from "../api";
import type { Ctx } from "../App";
import { Empty, useLoad } from "../ui";
import { TestResult, TestTable } from "./Events";

type Version = {
  version: number; active: boolean; published_at: string; published_by: string; comment: string;
  rolled_back_from: number | null; rules: number; exceptions: number; detection_rate: number | null; fp_rate: number | null;
};
type Changes = { active_version: number | null; changes: { type: string; id: string; change: string }[] };

export default function Policy({ ctx }: { ctx: Ctx }) {
  const isAdmin = atLeast(ctx.me.role, "ADMIN");
  const canEdit = atLeast(ctx.me.role, "OPERATOR");
  const changes = useLoad(() => api.get<Changes>("/policy/changes"));
  const versions = useLoad(() => (isAdmin ? api.get<Version[]>("/policy/versions") : Promise.resolve([] as Version[])));
  const [test, setTest] = useState<TestResult | null>(null);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);

  const runTest = async () => {
    setBusy(true);
    try {
      setTest(await api.post<TestResult>("/policy/test", {}));
    } catch (e) {
      ctx.toast(errorText(e), "err");
    } finally {
      setBusy(false);
    }
  };

  const publish = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ version: number }>("/policy/publish", { comment });
      ctx.toast(`정책 v${r.version}을 발행했습니다.`);
      setTest(null);
      setComment("");
      changes.reload();
      versions.reload();
      ctx.refreshChanges();
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        const d = e.body?.detail ?? e.body;
        setTest({
          passed: false, reasons: d.reasons ?? [], current: d.current, candidate: d.candidate,
          new_misses: d.new_misses ?? [], new_false_positives: d.new_false_positives ?? [],
          known_false_positives: { total: 0, still_blocked: 0 }, changes: changes.data?.changes ?? [],
        });
      }
      ctx.toast(errorText(e), "err");
    } finally {
      setBusy(false);
    }
  };

  const rollback = async (v: number) => {
    const reason = prompt(`v${v} 내용으로 되돌립니다(새 버전으로 발행). 사유를 입력하세요.`);
    if (reason === null) return;
    try {
      const r = await api.post<{ version: number }>(`/policy/rollback/${v}`, { reason });
      ctx.toast(`v${v}를 v${r.version}으로 다시 발행했습니다.`);
      versions.reload();
      changes.reload();
      ctx.refreshChanges();
    } catch (e) {
      ctx.toast(errorText(e), "err");
    }
  };

  const list = changes.data?.changes ?? [];

  return (
    <div className="stack">
      <h2>정책 버전</h2>
      <section className="card">
        <div className="row between">
          <h3>미발행 변경 {list.length}건 <span className="muted small">현재 발행본 v{changes.data?.active_version ?? "—"}</span></h3>
          {canEdit && (
            <button className="btn" onClick={runTest} disabled={busy || list.length === 0}>
              회귀 테스트 실행
            </button>
          )}
        </div>
        {list.length === 0 ? (
          <Empty>작업본이 발행본과 같습니다.</Empty>
        ) : (
          <ul className="list">
            {list.map((c, i) => (
              <li key={i}>
                <span className="badge gray">{c.type === "rule" ? "룰" : c.type === "exception" ? "예외" : "정책"}</span>{" "}
                <span className="mono">{c.id}</span> {c.change}
              </li>
            ))}
          </ul>
        )}
        {test && <TestTable t={test} />}
        {canEdit && list.length > 0 && (
          <div className="row">
            <input placeholder="발행 메모" value={comment} onChange={(e) => setComment(e.target.value)} className="grow" />
            <button className="btn primary" onClick={publish} disabled={busy}>
              {busy ? "처리 중…" : "발행"}
            </button>
          </div>
        )}
        <p className="small muted">발행할 때 서버가 회귀 테스트를 다시 실행해, 탐지율이 떨어지거나 차단 오탐이 늘면 거부합니다(422).</p>
      </section>

      {isAdmin && (
        <section className="card flush">
          <h3 className="pad">버전 이력</h3>
          <div className="scroll-x">
            <table className="table">
              <thead>
                <tr><th>버전</th><th>발행</th><th>메모</th><th className="num">룰</th><th className="num">예외</th><th className="num">탐지율</th><th className="num">오탐률</th><th /></tr>
              </thead>
              <tbody>
                {(versions.data ?? []).map((v) => (
                  <tr key={v.version}>
                    <td className="nowrap">v{v.version} {v.active && <span className="badge green">적용 중</span>}</td>
                    <td className="small">{fmtTime(v.published_at)}<br />{v.published_by}</td>
                    <td className="small">{v.comment}{v.rolled_back_from ? ` (v${v.rolled_back_from} 복원)` : ""}</td>
                    <td className="num">{v.rules}</td>
                    <td className="num">{v.exceptions}</td>
                    <td className="num">{fmtPct(v.detection_rate)}</td>
                    <td className="num">{fmtPct(v.fp_rate)}</td>
                    <td>{!v.active && <button className="btn small" onClick={() => rollback(v.version)}>이 버전으로 되돌리기</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
