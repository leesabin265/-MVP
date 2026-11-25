import { FormEvent, useState } from "react";
import { api, atLeast, errorText, fmtTime } from "../api";
import type { Ctx } from "../App";
import { Code, Modal, ModeBadge, useLoad } from "../ui";

type Rule = {
  id: string; category: string; kind: string; pattern?: string; keywords?: string[]; signal?: string; analyzer?: string;
  weight: number; mode: "BLOCK" | "DETECT"; description: string; enabled: boolean; updated_at: string;
  updated_by: string | null; published: boolean; dirty: boolean;
};

const CATS = ["SQLI", "XSS", "SCR", "ENC"];

export default function Rules({ ctx }: { ctx: Ctx }) {
  const { data, error, reload } = useLoad(() => api.get<Rule[]>("/rules"));
  const [cat, setCat] = useState("");
  const [edit, setEdit] = useState<Rule | "new" | null>(null);
  const canEdit = atLeast(ctx.me.role, "OPERATOR");

  const toggleMode = async (r: Rule) => {
    try {
      await api.patch(`/rules/${r.id}/mode`, { mode: r.mode === "BLOCK" ? "DETECT" : "BLOCK" });
      reload();
      ctx.refreshChanges();
    } catch (e) {
      ctx.toast(errorText(e), "err");
    }
  };
  const toggleEnabled = async (r: Rule) => {
    try {
      await api.patch(`/rules/${r.id}`, { enabled: !r.enabled });
      reload();
      ctx.refreshChanges();
    } catch (e) {
      ctx.toast(errorText(e), "err");
    }
  };

  if (error) return <div className="error">{errorText(error)}</div>;
  const rules = (data ?? []).filter((r) => !cat || r.category === cat);

  return (
    <div className="stack">
      <div className="row between">
        <h2>룰 ({data?.length ?? 0})</h2>
        <div className="row">
          <div className="seg">
            {["", ...CATS].map((c) => (
              <button key={c || "all"} className={cat === c ? "on" : ""} onClick={() => setCat(c)}>
                {c || "전체"}
              </button>
            ))}
          </div>
          {canEdit && (
            <button className="btn primary" onClick={() => setEdit("new")}>
              새 룰
            </button>
          )}
        </div>
      </div>
      <p className="muted small">모드 전환·수정은 ‘미발행 변경’으로 쌓이고, 정책 버전 화면에서 회귀 테스트 후 발행해야 게이트웨이에 반영됩니다.</p>
      <div className="card flush scroll-x">
        <table className="table">
          <thead>
            <tr>
              <th>ID</th><th>설명</th><th>종류</th><th>패턴 / 신호</th><th className="num">가중치</th><th>모드</th><th>사용</th><th>변경</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id} className={r.enabled ? "" : "dim"}>
                <td className="mono nowrap">
                  {canEdit ? <button className="link mono" onClick={() => setEdit(r)}>{r.id}</button> : r.id}
                </td>
                <td>{r.description}</td>
                <td>{r.kind}</td>
                <td className="pattern">
                  <Code>{r.pattern ?? r.signal ?? r.analyzer ?? ""}</Code>
                </td>
                <td className="num">{r.weight}</td>
                <td>
                  {canEdit ? (
                    <button className="link" onClick={() => toggleMode(r)} title="탐지 ↔ 차단 전환">
                      <ModeBadge mode={r.mode} />
                    </button>
                  ) : (
                    <ModeBadge mode={r.mode} />
                  )}
                </td>
                <td>
                  <input type="checkbox" checked={r.enabled} disabled={!canEdit} onChange={() => toggleEnabled(r)} aria-label={`${r.id} 사용`} />
                </td>
                <td className="small nowrap">
                  {r.dirty ? <span className="badge amber">{r.published ? "미발행" : "신규"}</span> : <span className="muted">{fmtTime(r.updated_at)}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {edit && (
        <RuleEditor
          rule={edit === "new" ? null : edit}
          onClose={() => setEdit(null)}
          onSaved={() => {
            setEdit(null);
            reload();
            ctx.refreshChanges();
            ctx.toast("저장했습니다. 발행해야 반영됩니다.");
          }}
        />
      )}
    </div>
  );
}

function RuleEditor({ rule, onClose, onSaved }: { rule: Rule | null; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({
    id: rule?.id ?? "",
    category: rule?.category ?? "XSS",
    pattern: rule?.pattern ?? "",
    keywords: (rule?.keywords ?? []).join(", "),
    weight: rule?.weight ?? 4,
    description: rule?.description ?? "",
  });
  const [err, setErr] = useState("");
  const isRegex = !rule || rule.kind === "regex";

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    const keywords = f.keywords.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
    try {
      if (rule) {
        const body: Record<string, unknown> = { weight: Number(f.weight), description: f.description };
        if (isRegex) Object.assign(body, { pattern: f.pattern, keywords });
        await api.patch(`/rules/${rule.id}`, body);
      } else {
        await api.post("/rules", {
          id: f.id.trim().toUpperCase(), category: f.category, pattern: f.pattern, keywords,
          weight: Number(f.weight), description: f.description,
        });
      }
      onSaved();
    } catch (ex) {
      setErr(errorText(ex));
    }
  };

  return (
    <Modal title={rule ? `룰 수정 ${rule.id}` : "새 룰 (기본 모드: 탐지)"} onClose={onClose} wide>
      <form className="stack" onSubmit={save}>
        <div className="form-grid">
          <label>ID<input value={f.id} disabled={!!rule} placeholder="XSS-015" onChange={(e) => setF({ ...f, id: e.target.value })} required /></label>
          <label>분류
            <select value={f.category} disabled={!!rule} onChange={(e) => setF({ ...f, category: e.target.value })}>
              {CATS.filter((c) => c !== "ENC").map((c) => <option key={c}>{c}</option>)}
            </select>
          </label>
          <label>가중치(1–10)<input type="number" min={1} max={10} value={f.weight} onChange={(e) => setF({ ...f, weight: Number(e.target.value) })} /></label>
          <label className="span3">설명<input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
          {isRegex && (
            <>
              <label className="span3">패턴 (RE2, 정규화된 소문자 텍스트에 적용)
                <textarea className="mono" rows={3} value={f.pattern} onChange={(e) => setF({ ...f, pattern: e.target.value })} required />
              </label>
              <label className="span3">프리필터 키워드 (쉼표 구분, 비우면 항상 정밀 분석)
                <input value={f.keywords} onChange={(e) => setF({ ...f, keywords: e.target.value })} />
              </label>
            </>
          )}
        </div>
        <p className="small muted">RE2는 역참조(\1)와 전후방 탐색(?=, ?&lt;!)을 지원하지 않습니다. 대신 선형 시간이 보장되어 ReDoS가 생기지 않습니다.</p>
        {err && <div className="error">{err}</div>}
        <div className="row">
          <button className="btn primary">저장</button>
          <button type="button" className="btn" onClick={onClose}>취소</button>
        </div>
      </form>
    </Modal>
  );
}
