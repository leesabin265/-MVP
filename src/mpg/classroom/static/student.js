// 학생 화면. 서버 상태를 1.5초마다 읽어 단계별 화면을 보여 준다.
// 사용자 입력·서버 값은 모두 textContent로만 넣는다(공격 문자열이 그대로 오가므로).
"use strict";
const $ = (id) => document.getElementById(id);
const views = ["join", "lobby", "vote", "reveal", "challenge", "end"];
let last = null;
let targetsFilled = false;

function show(name) {
  for (const v of views) $("v-" + v).hidden = v !== name;
}

async function api(path, body) {
  const r = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "요청 실패 (" + r.status + ")");
  return data;
}

function render(s) {
  $("who").textContent = s.nick ? s.nick : "";
  if (!s.joined) return show("join");
  if (s.phase === "lobby") return show("lobby");
  if (s.phase === "end") return show("end");
  if (s.phase === "vote") {
    $("q-title").textContent = s.question.title;
    $("q-shown").textContent = s.question.shown;
    $("q-hint").textContent = s.question.hint;
    $("vote-block").classList.toggle("picked", s.my_vote === "block");
    $("vote-pass").classList.toggle("picked", s.my_vote === "pass");
    $("vote-msg").textContent = s.my_vote ? "투표했어요. 바꿀 수도 있어요." : "";
    return show("vote");
  }
  if (s.phase === "reveal") {
    $("r-title").textContent = s.question.title;
    $("r-shown").textContent = s.question.shown;
    const res = s.result;
    if (res) {
      $("r-badge").textContent = res.blocked ? "🛡️ 막혔습니다" : "🚪 통과했습니다";
      $("r-badge").className = "badge-big " + (res.blocked ? "block" : "pass");
      const correct = s.my_vote && (s.my_vote === "block") === res.blocked;
      $("r-mine").textContent = !s.my_vote ? "" : correct ? "맞혔어요! 🎉" : "아쉬워요 😅";
      $("r-explain").textContent = res.explain;
    }
    return show("reveal");
  }
  if (s.phase === "challenge") {
    if (!targetsFilled) {
      for (const [k, label] of Object.entries(s.targets)) {
        const o = document.createElement("option");
        o.value = k;
        o.textContent = label;
        $("target").appendChild(o);
      }
      targetsFilled = true;
    }
    const ul = $("mine");
    ul.replaceChildren();
    for (const m of s.mine || []) {
      const li = document.createElement("li");
      const tag = document.createElement("span");
      tag.className = "pill " + (m.blocked ? "block" : m.verdict === "accepted" ? "win" : "pass");
      tag.textContent = m.blocked ? "차단" : m.verdict === "accepted" ? "인정!" : m.verdict === "rejected" ? "통과·불인정" : "통과·심사중";
      const code = document.createElement("code");
      code.textContent = m.payload;
      const where = document.createElement("span");
      where.className = "muted small";
      where.textContent = " " + m.target;
      li.append(tag, " ", code, where);
      ul.appendChild(li);
    }
    return show("challenge");
  }
}

async function tick() {
  try {
    const s = await api("/api/state");
    last = s;
    render(s);
  } catch (e) { /* 일시적인 네트워크 오류는 다음 주기에 다시 */ }
}

$("join-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/join", { nick: $("nick").value });
    tick();
  } catch (err) { alertInline($("nick"), err.message); }
});

for (const [id, choice] of [["vote-block", "block"], ["vote-pass", "pass"]]) {
  $(id).addEventListener("click", async () => {
    try { await api("/api/vote", { choice }); tick(); } catch (err) { $("vote-msg").textContent = err.message; }
  });
}

$("submit-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("send");
  btn.disabled = true;
  $("send-msg").textContent = "보내는 중…";
  try {
    const r = await api("/api/submit", { target: $("target").value, payload: $("payload").value, raw: $("raw").checked });
    $("send-msg").textContent = r.blocked ? "🛡️ 막혔어요! 다른 방법을 써 보세요" : "🚪 통과! 발표자가 심사합니다";
    $("send-msg").className = "big-text " + (r.blocked ? "block" : "pass");
    tick();
  } catch (err) {
    $("send-msg").textContent = err.message;
    $("send-msg").className = "big-text";
  } finally {
    setTimeout(() => { btn.disabled = false; }, 1500);
  }
});

function alertInline(el, msg) {
  el.setCustomValidity(msg);
  el.reportValidity();
  setTimeout(() => el.setCustomValidity(""), 2000);
}

tick();
setInterval(tick, 1500);
