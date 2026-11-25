import { FormEvent, useEffect, useState } from "react";
import { api, atLeast, errorText, fmtPct, fmtTime } from "../api";
import type { Ctx } from "../App";
import { ActionBadge, Code, Empty, Modal, ModeBadge } from "../ui";

type EventRow = {
  request_id: string; ts: string; client_ip: string | null; method: string; path: string; risk_score: number;
  action: string; policy_version: number; field_ref: string; masked_sample: string; false_positive: boolean;
  rules: string[] | null;
};
type Verdict = {
  action: string; risk_score: number; steps: { name: string; value: string }[]; signals: string[];
  candidates: string[];
  matches: { rule_id: string; field_ref: string; score: number; mode: string; excepted: boolean; evidence: string }[];
};
type Detail = EventRow & {
  matches: { rule_id: string; field_ref: string; score: number; mode: string; excepted: boolean }[];
  recomputed: Verdict | null; fp_marked_by: string | null; fp_marked_at: string | null; note: string;
};
type Draft = { rule_id: string; path: string; param: string; expires_in_days: number; source_request_id: string; reason: string };
type TestResult = {
  passed: boolean; reasons: string[]; warnings?: string[];
  current: Rates | null; candidate: Rates;
  new_misses: { payload: string; path: string; param: string }[];
  new_false_positives: { payload: string }[];
  known_false_positives: { total: number; still_blocked: number };
  changes: { type: string; id: string; change: string }[];
};
type Rates = { detection_rate: number; block_rate: number; fp_rate: number; block_fp_rate: number; attack_total: number; normal_total: number };

export default function Events({ ctx, focus, clearFocus }: { ctx: Ctx; focus: string | null; clearFocus: () => void }) {
  const [filters, setFilters] = useState({ q: "", action: "", rule: "", from: "", to: "" });
  const [items, setItems] = useState<EventRow[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<string | null>(focus);

  const query = (cur?: string | null) => {
    const p = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (!v) return;
      p.set(k, k === "from" || k === "to" ? new Date(v).toISOString() : v.trim());
    });
    if (cur) p.set("cursor", cur);
    p.set("limit", "50");
    return `/events?${p.toString()}`;
  };

  const load = async (append = false) => {
    setLoading(true);
    try {
      const r = await api.get<{ items: EventRow[]; next_cursor: string | null }>(query(append ? cursor : null));
      setItems(append ? [...items, ...r.items] : r.items);
      setCursor(r.next_cursor);
    } catch (e) {
      ctx.toast(errorText(e), "err");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    if (focus) {
      setSelected(focus);
      clearFocus();
    }
  }, [focus, clearFocus]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    load();
  };

  return (
    <div className="stack">
      <h2>탐지 로그</h2>
      <form className="filters card" onSubmit={submit}>
        <input placeholder="요청 ID · 경로 · IP · 샘플 검색" value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
        <select value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })} aria-label="조치">
          <option value="">전체 조치</option>
          <option value="BLOCK">차단</option>
          <option value="DETECT_ONLY">탐지</option>
        </select>
        <input placeholder="룰 ID (예: SQLI-002)" value={filters.rule} onChange={(e) => setFilters({ ...filters, rule: e.target.value.toUpperCase() })} className="short" />
        <input type="datetime-local" value={filters.from} onChange={(e) => setFilters({ ...filters, from: e.target.value })} aria-label="시작" />
        <input type="datetime-local" value={filters.to} onChange={(e) => setFilters({ ...filters, to: e.target.value })} aria-label="끝" />
        <button className="btn primary">검색</button>
      </form>

      <div className="card flush">
        {items.length === 0 && !loading ? (
          <Empty>조건에 맞는 이벤트가 없습니다.</Empty>
        ) : (
          <div className="scroll-x">
            <table className="table hover">
              <thead>
                <tr>
                  <th>시각</th><th>조치</th><th className="num">점수</th><th>메서드·경로</th><th>필드</th><th>룰</th><th>샘플</th><th>IP</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.request_id} onClick={() => setSelected(e.request_id)} className={selected === e.request_id ? "sel" : ""}>
                    <td className="nowrap">{fmtTime(e.ts)}</td>
                    <td>
                      <ActionBadge action={e.action} /> {e.false_positive && <span className="badge gray">오탐</span>}
                    </td>
                    <td className="num">{e.risk_score}</td>
                    <td className="mono nowrap">
                      {e.method} {e.path}
                    </td>
                    <td className="mono">{e.field_ref}</td>
                    <td className="mono">{(e.rules ?? []).join(", ")}</td>
                    <td className="sample">{e.masked_sample}</td>
                    <td className="mono">{e.client_ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="row pad">
          {cursor && (
            <button className="btn" onClick={() => load(true)} disabled={loading}>
              더 보기
            </button>
          )}
          {loading && <span className="muted">불러오는 중…</span>}
        </div>
      </div>
      {selected && <EventDetail id={selected} ctx={ctx} onClose={() => setSelected(null)} onChanged={() => load()} />}
    </div>
  );
}

function EventDetail({ id, ctx, onClose, onChanged }: { id: string; ctx: Ctx; onClose: () => void; onChanged: () => void }) {
  const [d, setD] = useState<Detail | null>(null);
  const [err, setErr] = useState("");
  const [draft, setDraft] = useState<{ draft: Draft; score_before: number; score_after_estimate: number } | null>(null);

  useEffect(() => {
    setD(null);
    api.get<Detail>(`/events/${id}`).then(setD).catch((e) => setErr(errorText(e)));
  }, [id]);

  const markFp = async () => {
    try {
      const r = await api.post<{ draft: Draft | null; score_before: number; score_after_estimate: number }>(`/events/${id}/false-positive`);
      setD(d && { ...d, false_positive: true });
      onChanged();
      if (r.draft) setDraft({ draft: r.draft, score_before: r.score_before, score_after_estimate: r.score_after_estimate });
      else ctx.toast("오탐으로 표시했습니다. 예외로 만들 룰이 없습니다.");
    } catch (e) {
      ctx.toast(errorText(e), "err");
    }
  };

  return (
    <Modal title="이벤트 상세" onClose={onClose} wide>
      {err && <div className="error">{err}</div>}
      {!d ? (
        <div className="muted">불러오는 중…</div>
      ) : (
        <div className="stack">
          <div className="kv">
            <div>요청 ID</div><div className="mono">{d.request_id}</div>
            <div>시각</div><div>{fmtTime(d.ts)}</div>
            <div>요청</div><div className="mono">{d.method} {d.path}</div>
            <div>판정</div><div><ActionBadge action={d.action} /> 점수 {d.risk_score} · 정책 v{d.policy_version}</div>
            <div>필드</div><div className="mono">{d.field_ref}</div>
            <div>출발지</div><div className="mono">{d.client_ip}</div>
            {d.false_positive && (<><div>오탐</div><div>{d.fp_marked_by} · {fmtTime(d.fp_marked_at)}</div></>)}
          </div>

          <section>
            <h4>매칭 룰 (기록 당시)</h4>
            <table className="table">
              <thead><tr><th>룰</th><th>필드</th><th>모드</th><th className="num">점수</th></tr></thead>
              <tbody>
                {d.matches.map((m, i) => (
                  <tr key={i} className={m.excepted ? "struck" : ""}>
                    <td className="mono">{m.rule_id}</td><td className="mono">{m.field_ref}</td>
                    <td><ModeBadge mode={m.mode} /></td>
                    <td className="num">{m.excepted ? "예외" : `+${m.score}`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          {d.recomputed ? (
            <section>
              <h4>파이프라인 단계 (재계산)</h4>
              <ol className="steps">
                {d.recomputed.steps.map((s, i) => (
                  <li key={i}>
                    <span className="step-name">{s.name}</span>
                    <Code>{s.value}</Code>
                  </li>
                ))}
              </ol>
              <p className="small muted">
                우회 신호: {d.recomputed.signals.join(", ") || "없음"} · 프리필터 후보 {d.recomputed.candidates.length}개 ·
                재계산 점수 {d.recomputed.risk_score}
              </p>
              <p className="small muted">{d.note}</p>
            </section>
          ) : (
            <p className="muted small">민감 필드라 샘플을 저장하지 않아 재계산할 수 없습니다.</p>
          )}

          {atLeast(ctx.me.role, "OPERATOR") && (
            <div className="row">
              <button className="btn primary" onClick={markFp}>
                {d.false_positive ? "예외 초안 다시 만들기" : "오탐 처리"}
              </button>
            </div>
          )}
        </div>
      )}
      {draft && <ExceptionFlow ctx={ctx} init={draft} onDone={() => { setDraft(null); onClose(); }} onCancel={() => setDraft(null)} />}
    </Modal>
  );
}

function ExceptionFlow({ ctx, init, onDone, onCancel }: {
  ctx: Ctx;
  init: { draft: Draft; score_before: number; score_after_estimate: number };
  onDone: () => void; onCancel: () => void;
}) {
  const [draft, setDraft] = useState(init.draft);
  const [savedId, setSavedId] = useState<number | null>(null);
  const [test, setTest] = useState<TestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const runTest = async () => {
    setBusy(true);
    setErr("");
    try {
      let id = savedId;
      if (id == null) {
        id = (await api.post<{ id: number }>("/exceptions", draft)).id;
        setSavedId(id);
        ctx.refreshChanges();
      }
      setTest(await api.post<TestResult>("/policy/test", {}));
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const publish = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ version: number }>("/policy/publish", { comment: draft.reason });
      ctx.toast(`정책 v${r.version} 발행. 게이트웨이가 몇 초 안에 반영합니다.`);
      ctx.refreshChanges();
      onDone();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    if (savedId != null) {
      await api.del(`/exceptions/${savedId}`).catch(() => {});
      ctx.refreshChanges();
    }
    onCancel();
  };

  return (
    <Modal title="오탐 예외 등록" onClose={cancel} wide>
      <div className="stack">
        <p className="muted small">
          예외는 룰 1개 · 경로 1개 · 파라미터 1개에만 적용되고, 만료일이 지나면 자동으로 빠집니다. 예상 점수 {init.score_before} → {init.score_after_estimate}
        </p>
        <div className="form-grid">
          <label>룰<input value={draft.rule_id} disabled={savedId != null} onChange={(e) => setDraft({ ...draft, rule_id: e.target.value })} /></label>
          <label>경로<input value={draft.path} disabled={savedId != null} onChange={(e) => setDraft({ ...draft, path: e.target.value })} /></label>
          <label>파라미터<input value={draft.param} disabled={savedId != null} onChange={(e) => setDraft({ ...draft, param: e.target.value })} /></label>
          <label>만료(일)<input type="number" min={1} max={180} value={draft.expires_in_days} disabled={savedId != null} onChange={(e) => setDraft({ ...draft, expires_in_days: Number(e.target.value) })} /></label>
          <label className="span2">사유<input value={draft.reason} disabled={savedId != null} onChange={(e) => setDraft({ ...draft, reason: e.target.value })} /></label>
        </div>
        {err && <div className="error">{err}</div>}
        {test && <TestTable t={test} />}
        <div className="row">
          {!test ? (
            <button className="btn primary" onClick={runTest} disabled={busy}>
              {busy ? "테스트 중…" : "회귀 테스트 실행"}
            </button>
          ) : (
            <button className="btn primary" onClick={publish} disabled={busy || !test.passed}>
              저장하고 발행
            </button>
          )}
          <button className="btn" onClick={cancel} disabled={busy}>
            취소{savedId != null ? "(초안 삭제)" : ""}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function TestTable({ t }: { t: TestResult }) {
  const rows: [string, keyof Rates, boolean][] = [
    ["탐지율", "detection_rate", true],
    ["차단율", "block_rate", true],
    ["오탐률(탐지 포함)", "fp_rate", false],
    ["차단 오탐률", "block_fp_rate", false],
  ];
  return (
    <div className="stack tight">
      <div className={t.passed ? "banner ok" : "banner crit"}>
        {t.passed ? "회귀 테스트 통과 — 발행할 수 있습니다." : `회귀 테스트 실패: ${t.reasons.join(", ")}`}
      </div>
      {(t.warnings ?? []).map((w) => (
        <div key={w} className="banner warn">
          {w.startsWith("block_rate_dropped")
            ? `차단율이 ${(Number(w.split(":")[1]) * 100).toFixed(2)}%p 내려갑니다(경로 임계값 완화 등). 해당 요청은 차단 대신 기록됩니다.`
            : w}
        </div>
      ))}
      <table className="table">
        <thead><tr><th>지표</th><th className="num">현재(발행본)</th><th className="num">변경 후</th></tr></thead>
        <tbody>
          {rows.map(([label, k, higherBetter]) => {
            const a = t.current?.[k] as number | undefined;
            const b = t.candidate[k] as number;
            const worse = a != null && (higherBetter ? b < a : b > a);
            return (
              <tr key={k}>
                <td>{label}</td>
                <td className="num">{fmtPct(a)}</td>
                <td className={worse ? "num bad" : "num"}>{fmtPct(b)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="small muted">
        공격 {t.candidate.attack_total}건 · 정상 {t.candidate.normal_total}건 · 오탐 표시된 이벤트 {t.known_false_positives.total}건 중 여전히 차단 {t.known_false_positives.still_blocked}건
      </p>
      {t.new_misses.length > 0 && (
        <details open>
          <summary>새로 놓치는 공격 {t.new_misses.length}건</summary>
          <ul className="list">{t.new_misses.slice(0, 20).map((m, i) => <li key={i}><Code>{m.payload}</Code></li>)}</ul>
        </details>
      )}
      {t.new_false_positives.length > 0 && (
        <details>
          <summary>새 오탐 {t.new_false_positives.length}건</summary>
          <ul className="list">{t.new_false_positives.slice(0, 20).map((m, i) => <li key={i}><Code>{m.payload}</Code></li>)}</ul>
        </details>
      )}
    </div>
  );
}

export type { TestResult };
