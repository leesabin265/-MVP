// 학생 화면. 서버 상태를 1.5초마다 읽어 단계별 화면을 보여 준다.
// 사용자 입력·서버 값은 모두 textContent로만 넣는다(공격 문자열이 그대로 오가므로).
"use strict";
const $ = (id) => document.getElementById(id);
const views = ["join", "lobby", "vote", "reveal", "challenge", "end"];
let last = null;
let cardsFilled = false;
let pickedAttack = null;
const pickedDisguises = new Set();

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
    if (!cardsFilled && s.cards) {
      for (const a of s.cards.attacks) {
        const b = document.createElement("button");
        b.className = "card attack";
        b.dataset.id = a.id;
        const t = document.createElement("b");
        t.textContent = a.label;
        const d = document.createElement("span");
        d.className = "muted small";
        d.textContent = a.desc;
        b.append(t, d);
        b.addEventListener("click", () => {
          pickedAttack = a.id;
          refreshCards();
        });
        $("attacks").appendChild(b);
      }
      for (const g of s.cards.disguises) {
        const b = document.createElement("button");
        b.className = "card disguise";
        b.dataset.id = g.id;
        const t = document.createElement("b");
        t.textContent = g.label;
        const d = document.createElement("span");
        d.className = "muted small";
        d.textContent = g.blurb;
        b.append(t, d);
        b.addEventListener("click", () => {
          if (pickedDisguises.has(g.id)) pickedDisguises.delete(g.id);
          else pickedDisguises.add(g.id);
          refreshCards();
        });
        $("disguises").appendChild(b);
      }
      cardsFilled = true;
      refreshCards();
    }
    const total = (s.cards?.attacks || []).length;
    const n = (s.cracked || []).length;
    $("crack-progress").textContent = `뚫은 공격 ${n} / ${total}` + (n === total && total ? "  🏆 전부 뚫었어요!" : "");
    const ul = $("mine");
    ul.replaceChildren();
    for (const m of s.mine || []) {
      const li = document.createElement("li");
      const tag = document.createElement("span");
      tag.className = "pill " + (m.blocked ? "block" : "pass");
      tag.textContent = m.blocked ? "막힘" : "통과!";
      const label = document.createElement("span");
      label.textContent = " " + m.attack + " ";
      const dg = document.createElement("span");
      dg.className = "muted small";
      dg.textContent = m.disguises.length ? m.disguises.join(" ") : "변장 없음";
      li.append(tag, label, dg);
      ul.appendChild(li);
    }
    return show("challenge");
  }
}

function refreshCards() {
  for (const b of document.querySelectorAll("#attacks .card")) b.classList.toggle("picked", b.dataset.id === pickedAttack);
  for (const b of document.querySelectorAll("#disguises .card")) b.classList.toggle("picked", pickedDisguises.has(b.dataset.id));
  $("send").disabled = !pickedAttack;
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

$("send").addEventListener("click", async () => {
  if (!pickedAttack) return;
  const btn = $("send");
  btn.disabled = true;
  const box = $("send-result");
  box.className = "send-result";
  box.textContent = "보내는 중…";
  try {
    const r = await api("/api/submit", { attack: pickedAttack, disguises: [...pickedDisguises] });
    box.className = "send-result " + (r.blocked ? "block" : "pass");
    const head = document.createElement("div");
    head.className = "big-text";
    head.textContent = r.blocked
      ? "🛡️ 막혔어요! 다른 변장을 써 보세요"
      : r.first_crack ? "🎉 뚫었다! 새 공격 성공 +1점" : "🚪 통과! (이미 뚫은 공격)";
    const code = document.createElement("code");
    code.textContent = "게이트웨이로 보낸 값: " + r.payload;
    box.replaceChildren(head, code);
    tick();
  } catch (err) {
    box.textContent = err.message;
  } finally {
    setTimeout(() => { if (pickedAttack) btn.disabled = false; }, 1500);
  }
});

function alertInline(el, msg) {
  el.setCustomValidity(msg);
  el.reportValidity();
  setTimeout(() => el.setCustomValidity(""), 2000);
}

tick();
setInterval(tick, 1500);
