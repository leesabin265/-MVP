// 발표자 화면. 주소의 ?key= 로 받은 발표자 키를 모든 요청에 붙인다.
// 학생 입력은 공격 문자열이므로 textContent로만 화면에 넣는다.
"use strict";
const $ = (id) => document.getElementById(id);
const KEY = new URLSearchParams(location.search).get("key") || "";
let S = null;

async function api(path, body) {
  const r = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: Object.assign({ "X-Presenter-Key": KEY }, body ? { "Content-Type": "application/json" } : {}),
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "요청 실패 (" + r.status + ")");
  return data;
}

function btn(label, onClick, cls) {
  const b = document.createElement("button");
  b.textContent = label;
  if (cls) b.className = cls;
  b.addEventListener("click", async () => {
    b.disabled = true;
    try { await onClick(); await tick(); } catch (e) { alert(e.message); } finally { b.disabled = false; }
  });
  return b;
}

function buildControls(s) {
  const nav = $("controls");
  nav.replaceChildren();
  const phase = (p, q) => () => api("/api/presenter/phase", q === undefined ? { phase: p } : { phase: p, q });
  nav.append(btn("대기(QR)", phase("lobby"), s.phase === "lobby" ? "on" : ""));
  for (let i = 0; i < s.quiz_len; i++) {
    const active = (s.phase === "vote" || s.phase === "reveal") && s.q === i;
    nav.append(btn("Q" + (i + 1) + " 투표", phase("vote", i), active && s.phase === "vote" ? "on" : ""));
    nav.append(btn("Q" + (i + 1) + " 공개", phase("reveal", i), active && s.phase === "reveal" ? "on" : ""));
  }
  nav.append(btn("챌린지", phase("challenge"), s.phase === "challenge" ? "on" : ""));
  nav.append(btn("종료", phase("end"), s.phase === "end" ? "on" : ""));
}

function show(name) {
  for (const v of ["lobby", "quiz", "challenge", "end"]) $("p-" + v).hidden = v !== name;
}

function fillBoard(el, rows) {
  el.replaceChildren();
  if (!rows.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "아직 뚫은 사람이 없습니다";
    el.appendChild(li);
  }
  for (const r of rows) {
    const li = document.createElement("li");
    li.textContent = r.nick + " — " + r.cracked + "개" + (r.cracked >= 3 ? " 👑" : "");
    el.appendChild(li);
  }
}

function render(s) {
  $("count").textContent = "참여 " + s.students + "명";
  if (!S || S.phase !== s.phase || S.q !== s.q) buildControls(s);
  S = s;
  if (s.phase === "lobby") {
    if (!$("qr").src) $("qr").src = "/api/presenter/qr.svg?key=" + encodeURIComponent(KEY);
    $("url").textContent = s.url;
    return show("lobby");
  }
  if (s.phase === "vote" || s.phase === "reveal") {
    const q = s.question;
    $("quiz-tag").textContent = "예측 투표 " + (s.q + 1) + " / " + s.quiz_len;
    $("quiz-title").textContent = q.title;
    $("quiz-shown").textContent = q.shown;
    $("quiz-hint").textContent = q.hint;
    const total = Math.max(1, s.votes.block + s.votes.pass);
    $("bar-block").style.width = (100 * s.votes.block / total) + "%";
    $("bar-pass").style.width = (100 * s.votes.pass / total) + "%";
    $("n-block").textContent = s.votes.block;
    $("n-pass").textContent = s.votes.pass;
    const showRes = s.phase === "reveal" && s.result;
    $("quiz-result").hidden = !showRes;
    $("quiz-explain").hidden = !showRes;
    if (showRes) {
      $("quiz-result").textContent = (s.result.blocked ? "🛡️ 막혔습니다" : "🚪 통과했습니다") + "  (HTTP " + s.result.status + ")";
      $("quiz-result").className = "badge-big " + (s.result.blocked ? "block" : "pass");
      $("quiz-explain").textContent = q.explain;
    }
    return show("quiz");
  }
  if (s.phase === "challenge") {
    const c = s.challenge;
    $("s-blocked").textContent = c.blocked;
    $("s-passed").textContent = c.passed;
    $("s-total").textContent = c.total;
    const pend = $("pending");
    pend.replaceChildren();
    for (const [, cr] of Object.entries(c.cracks)) {
      const li = document.createElement("li");
      li.className = "pending";
      const who = document.createElement("b");
      who.textContent = cr.label;
      const n = document.createElement("div");
      n.className = cr.count ? "cls-crack-n done" : "cls-crack-n";
      n.textContent = cr.count ? cr.count + "명 뚫음 🔓" : "아직 아무도 못 뚫음 🔒";
      li.append(who, n);
      pend.appendChild(li);
    }
    fillBoard($("board"), c.leaderboard);
    const rec = $("recent");
    rec.replaceChildren();
    for (const r of c.recent) {
      const li = document.createElement("li");
      const tag = document.createElement("span");
      tag.className = "pill " + (r.blocked ? "block" : "pass");
      tag.textContent = r.blocked ? "막힘" : "통과";
      li.append(tag, " " + r.nick + " ", document.createTextNode(r.attack + " "));
      const dg = document.createElement("span");
      dg.className = "muted small";
      dg.textContent = r.disguises.length ? r.disguises.join(" ") : "변장 없음";
      li.append(dg);
      rec.appendChild(li);
    }
    return show("challenge");
  }
  if (s.phase === "end") {
    fillBoard($("final-board"), s.challenge.leaderboard);
    return show("end");
  }
}

async function tick() {
  try { render(await api("/api/presenter/state")); } catch (e) { $("count").textContent = e.message; }
}

tick();
setInterval(tick, 1000);
