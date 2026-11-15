(function () {
"use strict";

const E = window.QuizyEngine;
const $ = id => document.getElementById(id);
const sdk = () => window.GameOSSDK;
const online = () => window.QuizyOnline;
const LETTERS = ["A", "B", "C", "D"];
const BOT_NAMES = ["Quizzy Bot", "Brainy Bot", "Pixel Bot"];
const BANNER_MS = 3200;
const REVEAL_MS = 3800;
const QUICK_REVEAL_MS = 2200;
const ANSWER_GRACE_MS = 600;
const SCREENS = ["menu", "lobby", "help", "game", "join", "browse", "achievements", "leaderboard"];

// net.role: "local" (solo or hosting) | "guest" (joined a friend's lobby). The host runs the quiz, guests only answer.
const net = { role: "local", peers: [], pending: [], hostPeer: null, friends: null, hostName: "", lobby: [], lobbyMode: E.DEFAULT_MODE, viaPublic: false };
let screen = "menu";
let pool = E.buildPool(window.QuizyBank, null);
let mySubjects = load("quizy-subjects", ["general", "nature", "movies"]).filter(id => E.subjectById[id]).slice(0, E.MAX_SUBJECTS);
let botsOn = load("quizy-bots", true) !== false;
let mode = E.modeById[load("quizy-mode", E.DEFAULT_MODE)] ? load("quizy-mode", E.DEFAULT_MODE) : E.DEFAULT_MODE;
let publicOn = false; // the lobby is open to anyone signed in to Game OS; never remembered between visits
let G = null;     // host-side game (only the host has the answers)
let view = null;  // what this player's screen is showing
const images = new Map();

function load(key, fallback) {
  try { const v = JSON.parse(localStorage.getItem(key)); return v == null ? fallback : v; } catch (_) { return fallback; }
}
function save(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {} }
const me = () => sdk().user.username;
const sleepFor = ms => new Promise(resolve => setTimeout(resolve, ms));

// ── Weekly questions ──────────────────────────────────────────────────────────
async function loadWeekly() {
  try {
    const response = await fetch("weekly.json", { cache: "no-cache" });
    if (!response.ok) throw new Error("no weekly set");
    pool = E.buildPool(window.QuizyBank, await response.json());
  } catch (_) { /* offline or no weekly set yet: the questions that ship with the game are used */ }
  const fresh = pool.weeklyIds.size;
  $("week-label").textContent = `WEEK ${pool.week.split("-W")[1]}${fresh ? ` · ${fresh} NEW` : ""} ·`;
}

// ── Screens ───────────────────────────────────────────────────────────────────
function showScreen(name) {
  screen = name;
  for (const id of SCREENS) $(id).classList.toggle("hidden", id !== name);
  if (sdk()) sdk().setRunning(name === "game");
  if (name === "lobby") { renderLobby(); if (net.role === "local") loadFriends(); }
  if (name === "achievements") renderAchievements();
  if (name === "leaderboard") renderLeaderboard();
  if (name === "browse") renderBrowse();
  if (name === "menu") { cancelPendingInvites(); if (online()) online().closeRoom(); publicOn = false; net.viaPublic = false; stopSpeech(); }
  window.scrollTo(0, 0);
}
document.querySelectorAll("[data-go]").forEach(button => button.addEventListener("click", () => showScreen(button.dataset.go)));
$("play-button").addEventListener("click", () => { net.role = "local"; showScreen("lobby"); });
$("how-button").addEventListener("click", () => showScreen("help"));
$("online-button").addEventListener("click", () => { net.role = "local"; showScreen("browse"); });
$("lobby-back").addEventListener("click", () => { if (net.role === "guest") leaveOnline(); else { dropAllPeers(); showScreen("menu"); } });

// ── Lobby ─────────────────────────────────────────────────────────────────────
function toggleSubject(id) {
  const index = mySubjects.indexOf(id);
  if (index >= 0) mySubjects.splice(index, 1);
  else if (mySubjects.length < E.MAX_SUBJECTS) mySubjects.push(id);
  save("quizy-subjects", mySubjects);
  if (net.role === "guest" && net.hostPeer) net.hostPeer.send({ k: "subjects", list: mySubjects });
  else broadcastLobby();
  renderLobby();
}

function setMode(id) {
  if (!E.modeById[id] || G) return;
  mode = id;
  save("quizy-mode", mode);
  if (online() && (publicOn || net.peers.length)) online().setInfo({ mode });
  broadcastLobby();
  renderLobby();
}

function lobbyPlayers() {
  return [{ n: me(), sub: mySubjects }].concat(net.peers.map(p => ({ n: p.name, sub: p.subjects })));
}

function broadcastLobby() {
  const msg = { k: "lobby", host: me(), mode, players: lobbyPlayers() };
  net.peers.forEach(p => p.peer.send(msg));
}

function subjectNames(list) { return (list || []).map(id => E.subjectById[id] ? E.subjectById[id].name : id).join(", "); }

function renderLobby() {
  const guest = net.role === "guest";
  $("host-panel").classList.toggle("hidden", guest);
  $("guest-panel").classList.toggle("hidden", !guest);
  $("lobby-title").firstChild.textContent = guest ? `${net.hostName}'S LOBBY` : "THE LOBBY";
  $("bots").checked = botsOn;
  $("public").checked = publicOn;
  const shown = guest ? net.lobbyMode : mode;
  const modeGrid = $("mode-grid");
  modeGrid.replaceChildren();
  for (const m of E.MODES) {
    const button = document.createElement("button");
    button.className = "subject";
    button.type = "button";
    button.setAttribute("aria-pressed", String(m.id === shown));
    button.disabled = guest && m.id !== shown;
    const icon = document.createElement("i");
    icon.textContent = m.icon;
    button.append(icon, document.createTextNode(m.name));
    button.addEventListener("click", () => setMode(m.id));
    modeGrid.append(button);
  }
  $("mode-name").textContent = (E.modeById[shown] || E.modeById[E.DEFAULT_MODE]).name.toUpperCase();
  $("mode-desc").textContent = (E.modeById[shown] || E.modeById[E.DEFAULT_MODE]).blurb;
  const grid = $("subject-grid");
  grid.replaceChildren();
  for (const s of E.SUBJECTS) {
    const on = mySubjects.includes(s.id);
    const button = document.createElement("button");
    button.className = "subject";
    button.type = "button";
    button.setAttribute("aria-pressed", String(on));
    button.disabled = !on && mySubjects.length >= E.MAX_SUBJECTS;
    const icon = document.createElement("i");
    icon.textContent = s.icon;
    button.append(icon, document.createTextNode(s.name));
    button.addEventListener("click", () => toggleSubject(s.id));
    grid.append(button);
  }
  $("pick-count").textContent = `${mySubjects.length} / ${E.MAX_SUBJECTS} (MIN ${E.MIN_SUBJECTS})`;

  const humans = guest ? net.lobby : lobbyPlayers();
  const list = $("player-list");
  list.replaceChildren();
  const card = (name, text, tag, empty) => {
    const el = document.createElement("div");
    el.className = "player-card" + (empty ? " empty" : "");
    const title = document.createElement("strong");
    title.textContent = name;
    if (tag) { const t = document.createElement("span"); t.className = "tag"; t.textContent = tag; title.append(t); }
    const small = document.createElement("small");
    small.textContent = text;
    el.append(title, small);
    list.append(el);
  };
  humans.forEach((p, i) => card(p.n, p.sub && p.sub.length ? subjectNames(p.sub) : "Choosing subjects…", p.n === me() ? "YOU" : i === 0 ? "HOST" : ""));
  for (let i = humans.length; i < E.MAX_PLAYERS; i++) {
    if (!guest && botsOn) card(BOT_NAMES[i - 1] || "Bot", "Random subjects", "BOT");
    else card("Empty seat", guest ? "" : "Invite a friend or turn on bots", "", true);
  }
  $("player-count").textContent = `${humans.length} / ${E.MAX_PLAYERS}`;
  $("lobby-error").textContent = "";
}
$("public").addEventListener("change", event => setPublicOn(event.target.checked));
$("bots").addEventListener("change", event => { botsOn = event.target.checked; save("quizy-bots", botsOn); renderLobby(); });

// ── Host: running the quiz ────────────────────────────────────────────────────
const fmt = n => "£" + Number(n).toLocaleString("en-GB");
const MILLION_NAMES = ["Gran", "Uncle Bob", "Pub Quiz Pete", "Cousin Dee", "Nan"];

function startGame() {
  const error = $("lobby-error");
  if (!E.validPicks(mySubjects)) { error.textContent = `Pick ${E.MIN_SUBJECTS} to ${E.MAX_SUBJECTS} subjects first.`; return; }
  const waiting = net.peers.find(p => !E.validPicks(p.subjects));
  if (waiting) { error.textContent = `${waiting.name} hasn't picked their subjects yet.`; return; }
  const players = [{ name: me(), human: true, subjects: mySubjects }].concat(net.peers.map(p => ({ name: p.name, human: true, peer: p.peer, subjects: p.subjects })));
  if (botsOn) {
    for (let i = 0; players.length < E.MAX_PLAYERS; i++) {
      players.push({ name: BOT_NAMES[i], human: false, skill: 0.5 + Math.random() * 0.35, subjects: E.shuffle(E.SUBJECTS.map(s => s.id)).slice(0, 3) });
    }
  }
  for (const p of players) Object.assign(p, { score: 0, streak: 0, bestStreak: 0, correct: 0, total: 0, spelled: 0, picCorrect: 0, picTotal: 0, quickCorrect: 0, gone: false, escaped: false, finalWon: false });
  G = { mode, players, dead: false, seq: 0, public: publicOn, note: "", online: net.peers.length > 0 };
  if (online() && (publicOn || net.peers.length)) online().setInfo({ open: false });
  if (mode === "chase") runChase(G);
  else if (mode === "millionaire") runMillionaire(G);
  else {
    G.rounds = E.buildQuiz(pool, players.map(p => p.subjects), { picture: navigator.onLine !== false });
    G.flat = G.rounds.flatMap((round, ri) => round.questions.map((q, qi) => ({ q, ri, qi })));
    runGame(G);
  }
}
$("start-button").addEventListener("click", startGame);

function bcast(msg) {
  net.peers.forEach(p => p.peer.send(msg));
  onMessage(msg);
}

function deliver(name, msg) {
  if (name === me()) onMessage(msg);
  else { const entry = net.peers.find(p => p.name === name); if (entry) entry.peer.send(msg); }
}

function startMessage(g) {
  return { k: "start", mode: g.mode, players: g.players.map(p => p.name), online: g.online };
}

async function say(g, title, blurb, ms) {
  bcast({ k: "round", name: title, blurb, kind: "info", pre: [], ms: ms || BANNER_MS });
  await sleepFor(ms || BANNER_MS);
}

async function runGame(g) {
  bcast(startMessage(g));
  let lastRound = -1;
  for (let n = 0; n < g.flat.length && !g.dead; n++) {
    const { q, ri, qi } = g.flat[n];
    if (ri !== lastRound) {
      lastRound = ri;
      const round = g.rounds[ri];
      bcast({ k: "round", name: round.name, blurb: round.blurb, kind: round.kind, pre: round.kind === "picture" ? round.questions.map(x => x.wiki) : [] });
      await sleepFor(BANNER_MS);
      if (g.dead) return;
    }
    await ask(g, n, q, ri, qi);
  }
  if (!g.dead) finishGame(g);
}

function botAnswer(p, q) {
  const odds = p.skill * (q.type === "spell" ? 0.6 : q.type === "pic" ? 0.8 : 1);
  const right = Math.random() < odds;
  const ms = q.secs * 1000 * (0.2 + Math.random() * 0.6);
  let a;
  if (q.type === "spell") a = right ? q.word : q.word.slice(0, -1);
  else a = right ? q.answer : [0, 1, 2, 3].filter(i => i !== q.answer)[Math.floor(Math.random() * 3)];
  return { a, ms };
}

/**
 * Sends a question and waits for the players in `o.who` (default: everybody) to answer, or for the time to run out.
 * Everyone else just watches. Returns the question's state, or null if the game was ended meanwhile.
 */
async function collect(g, q, o) {
  const start = Date.now();
  const who = new Set(o.who || g.players.map(p => p.name));
  const cur = g.cur = { n: o.n, q, start, answers: new Map(), who, botMs: 0, finishing: false, done: null, timer: null };
  g.players.filter(p => !p.human && who.has(p.name)).forEach(p => {
    const answer = (o.bot || botAnswer)(p, q);
    cur.answers.set(p.name, answer);
    cur.botMs = Math.max(cur.botMs, answer.ms);
  });
  bcast(Object.assign({ k: "q", n: o.n, total: o.total || 0, q: E.publicQuestion(q) }, o.msg || {}, o.who ? { who: o.who } : {}));
  await new Promise(resolve => {
    cur.done = resolve;
    cur.timer = setTimeout(resolve, q.secs * 1000 + ANSWER_GRACE_MS);
    checkAllAnswered(g);
  });
  clearTimeout(cur.timer);
  if (g.dead) return null;
  g.cur = null;
  return cur;
}

// How long and what a player answered; null when they didn't answer in time.
function answerOf(cur, name) {
  const entry = cur.answers.get(name);
  const ms = entry ? (entry.ms != null ? entry.ms : entry.at - cur.start) : null;
  return entry && ms <= cur.q.secs * 1000 + ANSWER_GRACE_MS ? { a: entry.a, ms } : null;
}

function tally(p, q, ok) {
  p.total++;
  if (q.type === "pic") p.picTotal++;
  if (ok) {
    p.streak++;
    p.bestStreak = Math.max(p.bestStreak, p.streak);
    p.correct++;
    if (q.type === "spell") p.spelled++;
    if (q.type === "pic") p.picCorrect++;
    if (q.kind === "quickfire") p.quickCorrect++;
  } else p.streak = 0;
}

const optionText = (q, a) => q.type === "spell" ? String(a) : a === -1 ? "Walked away" : q.options[a];
const scoresOf = g => g.players.map(p => ({ n: p.name, s: p.score, st: p.streak, tag: p.tag || "" }));

async function ask(g, n, q, ri, qi) {
  const cur = await collect(g, q, { n, total: g.flat.length, msg: { r: ri, qi, rc: g.rounds[ri].questions.length } });
  if (!cur) return;
  const results = g.players.map(p => {
    const got = answerOf(cur, p.name);
    const ok = !!got && E.isCorrect(q, got.a);
    tally(p, q, ok);
    const pts = E.points(q, ok, 1 - Math.min(got ? got.ms : q.secs * 1000, q.secs * 1000) / (q.secs * 1000), p.streak - 1);
    p.score += pts;
    return { n: p.name, a: got ? optionText(q, got.a) : "", ok, pts };
  });
  bcast({ k: "reveal", n, correct: q.type === "spell" ? q.word : q.options[q.answer], results, scores: scoresOf(g) });
  await sleepFor(q.kind === "quickfire" ? QUICK_REVEAL_MS : REVEAL_MS);
}

function checkAllAnswered(g) {
  const cur = g.cur;
  if (!cur || !cur.done || cur.finishing) return;
  const humans = g.players.filter(p => p.human && !p.gone && cur.who.has(p.name));
  if (!humans.every(p => cur.answers.has(p.name))) return;
  cur.finishing = true;
  // With only bots answering, wait about as long as they "think" so the question doesn't flash past.
  setTimeout(cur.done, humans.length ? 400 : Math.max(400, cur.botMs - (Date.now() - cur.start)));
}

function acceptAnswer(name, n, a) {
  const g = G;
  if (!g || !g.cur || g.cur.n !== n || g.cur.answers.has(name) || !g.cur.who.has(name)) return;
  const q = g.cur.q;
  if (Date.now() > g.cur.start + q.secs * 1000 + ANSWER_GRACE_MS) return;
  if (q.type === "spell") { if (typeof a !== "string") return; a = a.slice(0, 64); }
  else if (g.mode === "millionaire" && a === -1) { /* walking away */ }
  else if (!Number.isInteger(a) || a < 0 || a >= q.options.length) return;
  g.cur.answers.set(name, { a, at: Date.now() });
  bcast({ k: "got", n, who: name });
  checkAllAnswered(g);
}

// ── The Chase ─────────────────────────────────────────────────────────────────
function chaserAnswer(q, right) {
  return q.options[right ? q.answer : [0, 1, 2, 3].filter(i => i !== q.answer)[Math.floor(Math.random() * 3)]];
}

async function runChase(g) {
  const C = E.CHASE;
  bcast(startMessage(g));
  const deck = E.makeDeck(pool, g.players.map(p => p.subjects));
  const botMs = () => 1500 + Math.random() * 2500;
  const botPick = (p, q) => q.kind === "offer"
    ? { a: [0, 1, 1, 1, 2][Math.floor(Math.random() * 5)], ms: botMs() }
    : { a: Math.random() < p.skill ? q.answer : [0, 1, 2, 3].filter(i => i !== q.answer)[Math.floor(Math.random() * 3)], ms: botMs() };

  await say(g, "The Cash Builder", `${C.cashQuestions} questions. Every right answer adds ${fmt(C.cashPerAnswer)} to your bank.`);
  for (let i = 0; i < C.cashQuestions && !g.dead; i++) {
    const q = deck.draw({ frac: 0.1 + 0.08 * i, secs: C.cashSecs });
    const cur = await collect(g, q, { n: ++g.seq, total: 0, bot: botPick, msg: { count: `CASH BUILDER ${i + 1} / ${C.cashQuestions}`, label: "CASH BUILDER" } });
    if (!cur) return;
    const results = g.players.map(p => {
      const got = answerOf(cur, p.name);
      const ok = !!got && E.isCorrect(q, got.a);
      tally(p, q, ok);
      if (ok) p.score += C.cashPerAnswer;
      return { n: p.name, a: got ? optionText(q, got.a) : "", ok, t: ok ? `+${fmt(C.cashPerAnswer)}` : "£0" };
    });
    bcast({ k: "reveal", n: cur.n, correct: q.options[q.answer], results, scores: scoresOf(g) });
    await sleepFor(QUICK_REVEAL_MS);
  }

  for (const p of g.players) {
    if (g.dead) return;
    p.cash = p.score;
    if (p.gone) { p.tag = "CAUGHT"; p.score = 0; continue; }
    await say(g, `${p.name} faces the Chaser`, `Cash built: ${fmt(p.cash)}. Choose an offer: higher pays more but starts closer to the Chaser.`, 2600);
    const offers = E.chaseOffers(p.cash);
    const offerQ = {
      type: "mc", kind: "offer", subject: "chase", prompt: `${p.name}, choose your offer`, secs: C.offerSecs, answer: 1,
      options: offers.map(o => `${o.label}: ${fmt(o.money)} (${o.start} ${o.start === 1 ? "step" : "steps"} ahead of the Chaser)`)
    };
    const picked = await collect(g, offerQ, { n: ++g.seq, who: [p.name], bot: botPick, msg: { count: "CHOOSE YOUR OFFER", label: "THE OFFER" } });
    if (!picked) return;
    const choice = answerOf(picked, p.name);
    const offer = offers[choice && offers[choice.a] ? choice.a : 1];
    p.offer = offer;
    p.score = offer.money;
    let board = { pos: offer.start, chaser: 0, steps: C.steps, outcome: "on" };
    await say(g, `${p.name} takes ${fmt(offer.money)}`, `Starting ${offer.start} ${offer.start === 1 ? "step" : "steps"} ahead. Reach home to keep it!`, 2200);

    for (let turn = 0; board.outcome === "on" && !g.dead; turn++) {
      const q = deck.draw({ frac: 0.3 + Math.random() * 0.4, secs: C.headSecs });
      const cur = await collect(g, q, {
        n: ++g.seq, who: [p.name], bot: botPick,
        msg: { count: `${p.name.toUpperCase()} VS THE CHASER`, label: "HEAD TO HEAD", board: { pos: board.pos, chaser: board.chaser, steps: C.steps, name: p.name, money: offer.money } }
      });
      if (!cur) return;
      const got = answerOf(cur, p.name);
      const ok = !!got && E.isCorrect(q, got.a);
      const chaserRight = Math.random() < C.chaserAccuracy;
      tally(p, q, ok);
      board = E.chaseStep(board, ok, chaserRight);
      bcast({
        k: "reveal", n: cur.n, correct: q.options[q.answer], scores: scoresOf(g),
        board: { pos: board.pos, chaser: board.chaser, steps: C.steps, name: p.name, money: offer.money },
        results: [
          { n: p.name, a: got ? optionText(q, got.a) : "", ok, t: ok ? "▼ 1 step" : "stays put" },
          { n: "The Chaser", a: chaserAnswer(q, chaserRight), ok: chaserRight, t: chaserRight ? "▼ 1 step" : "" }
        ]
      });
      await sleepFor(2800);
    }
    if (g.dead) return;
    if (board.outcome === "home") {
      p.escaped = true;
      p.tag = "HOME";
      await say(g, `🏠 ${p.name} is home!`, `${fmt(offer.money)} is safe for the final chase.`, 2400);
    } else {
      p.tag = "CAUGHT";
      p.score = 0;
      await say(g, `❌ ${p.name} was caught!`, "The Chaser takes it all.", 2400);
    }
  }

  if (g.dead) return;
  const team = g.players.filter(p => p.escaped && !p.gone);
  if (!team.length) {
    g.note = "The Chaser wins. Nobody made it home.";
    await say(g, "The Chaser wins", "Nobody made it home.", 2600);
    return finishGame(g);
  }
  const pot = team.reduce((sum, p) => sum + p.offer.money, 0);
  const share = Math.floor(pot / team.length / 100) * 100;
  await say(g, "The Final Chase", `${team.map(p => p.name).join(", ")} work as a team: any right answer scores a point. Beat the Chaser to share ${fmt(pot)}.`, 4000);
  let teamScore = 0;
  const names = team.map(p => p.name);
  for (let i = 0; i < C.finalQuestions && !g.dead; i++) {
    const q = deck.draw({ frac: 0.25 + Math.random() * 0.4, secs: C.finalSecs });
    const cur = await collect(g, q, { n: ++g.seq, who: names, bot: botPick, msg: { count: `FINAL CHASE ${i + 1} / ${C.finalQuestions}`, label: `Team score ${teamScore}` } });
    if (!cur) return;
    let anyone = false;
    const results = team.map(p => {
      const got = answerOf(cur, p.name);
      const ok = !!got && E.isCorrect(q, got.a);
      tally(p, q, ok);
      anyone = anyone || ok;
      return { n: p.name, a: got ? optionText(q, got.a) : "", ok, t: ok ? "+1 for the team" : "" };
    });
    if (anyone) teamScore++;
    bcast({ k: "reveal", n: cur.n, correct: q.options[q.answer], results, scores: scoresOf(g), note: `Team score: ${teamScore}` });
    await sleepFor(1800);
  }
  if (g.dead) return;
  let chaserScore = 0;
  for (let i = 0; i < C.finalQuestions; i++) if (Math.random() < C.finalChaserAccuracy) chaserScore++;
  const won = E.finalChaseWon(teamScore, chaserScore);
  team.forEach(p => { p.finalWon = won; p.score = won ? share : 0; p.tag = won ? "WON" : "CAUGHT"; });
  g.note = won ? `The team beat the Chaser ${teamScore} to ${chaserScore} and shared ${fmt(pot)}.` : `The Chaser caught the team: ${chaserScore} to ${teamScore}.`;
  await say(g, won ? "🏆 The team beats the Chaser!" : "The Chaser wins", `${g.note}`, 4000);
  finishGame(g);
}

// ── Millionaire ───────────────────────────────────────────────────────────────
function millionaireBot(p, q) {
  const level = q.level;
  const walk = level >= 10 && Math.random() < 0.25;
  const right = Math.random() < p.skill * (1 - level * 0.035);
  return { a: walk ? -1 : right ? q.answer : [0, 1, 2, 3].filter(i => i !== q.answer)[Math.floor(Math.random() * 3)], ms: 2000 + Math.random() * 4000 };
}

function hostLifeline(name, n, type) {
  const g = G;
  if (!g || g.mode !== "millionaire" || !g.cur || g.cur.n !== n) return;
  const p = g.players.find(x => x.name === name);
  if (!p || p.mstatus !== "playing" || !p.life[type] || g.cur.answers.has(name)) return;
  const q = g.cur.q;
  p.life[type] = false;
  const hint = { k: "hint", n, t: type };
  if (type === "fifty") { p.hidden = E.fiftyFifty(q.answer, q.options.length); hint.hide = p.hidden; }
  else if (type === "audience") hint.votes = E.audienceVote(q.answer, q.options.length, q.level, p.hidden);
  else Object.assign(hint, E.phoneFriend(q.answer, q.options.length, q.level, p.hidden), { who: MILLION_NAMES[Math.floor(Math.random() * MILLION_NAMES.length)] });
  deliver(name, hint);
}

async function runMillionaire(g) {
  const steps = E.LADDER.length;
  bcast(startMessage(g));
  g.players.forEach(p => Object.assign(p, { lvl: 0, mstatus: "playing", life: { fifty: true, audience: true, phone: true }, hidden: [] }));
  const deck = E.makeDeck(pool, g.players.map(p => p.subjects));
  await say(g, "Millionaire", `${steps} questions to ${fmt(E.LADDER[steps - 1])}. A wrong answer drops you to your last safe haven (${E.SAFE_AFTER.map(n => fmt(E.LADDER[n - 1])).join(" and ")}). Or walk away.`, 4500);

  for (let level = 0; level < steps && !g.dead; level++) {
    g.players.forEach(p => { if (p.mstatus === "playing" && p.gone) { p.mstatus = "walked"; p.tag = "LEFT"; } });
    const active = g.players.filter(p => p.mstatus === "playing");
    if (!active.length) break;
    active.forEach(p => { p.hidden = []; });
    const q = deck.draw({ frac: level / (steps - 1), secs: level < 5 ? 30 : level < 10 ? 45 : 60 });
    q.level = level;
    const cur = await collect(g, q, {
      n: ++g.seq, total: steps, who: active.map(p => p.name), bot: millionaireBot,
      msg: { count: `QUESTION ${level + 1} / ${steps}`, label: `FOR ${fmt(E.LADDER[level])}`, ml: { level } }
    });
    if (!cur) return;
    const results = active.map(p => {
      const got = answerOf(cur, p.name);
      if (got && got.a === -1) {
        p.mstatus = "walked";
        p.tag = "WALKED";
        return { n: p.name, a: "Walked away", ok: true, t: `Takes ${fmt(p.score)}` };
      }
      const ok = !!got && E.isCorrect(q, got.a);
      tally(p, q, ok);
      if (ok) {
        p.lvl++;
        p.score = E.winnings(p.lvl, false);
        if (p.lvl === steps) { p.mstatus = "won"; p.tag = "MILLIONAIRE"; }
      } else {
        p.score = E.winnings(p.lvl, true);
        p.mstatus = "out";
        p.tag = "OUT";
      }
      return { n: p.name, a: got ? optionText(q, got.a) : "", ok, t: ok ? fmt(p.score) : `Drops to ${fmt(p.score)}` };
    });
    bcast({ k: "reveal", n: cur.n, correct: q.options[q.answer], results, scores: scoresOf(g) });
    await sleepFor(REVEAL_MS);
  }
  if (g.dead) return;
  const rich = g.players.filter(p => p.mstatus === "won");
  g.note = rich.length ? `${rich.map(p => p.name).join(" and ")} won ${fmt(E.LADDER[steps - 1])}!` : "";
  finishGame(g);
}

function finishGame(g) {
  const ranked = E.ranking(g.players.map(p => ({ name: p.name, score: p.score, correct: p.correct })));
  const stats = {};
  g.players.forEach(p => {
    stats[p.name] = {
      correct: p.correct, total: p.total, bestStreak: p.bestStreak, spelled: p.spelled, picCorrect: p.picCorrect, picTotal: p.picTotal, quickCorrect: p.quickCorrect,
      subjects: p.subjects, escaped: p.escaped, finalWon: p.finalWon, millionaire: p.mstatus === "won"
    };
  });
  const humans = g.players.filter(p => p.human).length;
  bcast({
    k: "end", mode: g.mode, note: g.note, ranking: ranked.map(r => ({ n: r.name, s: r.score, c: r.correct, place: r.place })), stats,
    rivals: g.players.length - 1, online: humans > 1
  });
  G = null;
  if (online() && (publicOn || net.peers.length)) online().setInfo({ open: true });
  broadcastLobby();
}

function endGameEarly(message) {
  if (G) { G.dead = true; clearTimeout(G.cur && G.cur.timer); if (G.cur && G.cur.done) G.cur.done(); }
  G = null;
  net.peers.forEach(p => p.peer.send({ k: "abort", msg: message }));
  if (online() && (publicOn || net.peers.length)) online().setInfo({ open: true });
}

// ── Players: what every screen does with the host's messages ─────────────────
function onMessage(msg) {
  if (!msg) return;
  if (msg.k === "start") {
    view = {
      players: msg.players.map(n => ({ n, s: 0, st: 0, tag: "", done: false })), n: -1, answered: false, timer: null, online: !!msg.online,
      mode: E.modeById[msg.mode] ? msg.mode : E.DEFAULT_MODE, life: { fifty: true, audience: true, phone: true }, watch: false
    };
    hideOverlays();
    showScreen("game");
    $("reveal").classList.add("hidden");
    renderScoreboard();
    $("q-prompt").textContent = "Get ready…";
    $("q-options").replaceChildren();
    $("spell-form").classList.add("hidden");
    $("q-image-wrap").classList.add("hidden");
    $("q-count").textContent = "";
    $("q-subject").textContent = "";
    $("mode-info").classList.add("hidden");
    $("lifelines").classList.add("hidden");
    $("hint").classList.add("hidden");
    sdk().report("start", { online: !!msg.online, mode: view.mode });
  } else if (!view) return;
  else if (msg.k === "round") showRound(msg);
  else if (msg.k === "q") showQuestion(msg);
  else if (msg.k === "got") { const p = view.players.find(x => x.n === msg.who); if (p) { p.done = true; renderScoreboard(); } }
  else if (msg.k === "reveal") showReveal(msg);
  else if (msg.k === "hint") showHint(msg);
  else if (msg.k === "end") showEnd(msg);
  else if (msg.k === "abort") showAbort(msg.msg);
}

function hideOverlays() {
  $("round-banner").classList.add("hidden");
  $("game-over").classList.add("hidden");
}

function renderScoreboard() {
  const board = $("scoreboard");
  board.replaceChildren();
  for (const p of view.players) {
    const el = document.createElement("div");
    el.className = "score" + (p.n === me() ? " me" : "") + (p.done ? " done" : "");
    el.textContent = p.n;
    const strong = document.createElement("strong");
    strong.textContent = view.mode === "pub" ? p.s.toLocaleString() : fmt(p.s);
    el.append(strong);
    if (p.tag) { const em = document.createElement("em"); em.textContent = p.tag; el.append(em); }
    else if (view.mode === "pub" && p.st >= 2) { const em = document.createElement("em"); em.textContent = `🔥 ${p.st}`; el.append(em); }
    board.append(el);
  }
}

let bannerTimer = null;
function showRound(msg) {
  stopTimer();
  $("round-label").textContent = msg.name.toUpperCase();
  $("banner-title").textContent = msg.name;
  $("banner-blurb").textContent = msg.blurb;
  $("round-banner").classList.remove("hidden");
  $("q-status").textContent = "";
  $("reveal").classList.add("hidden");
  clearTimeout(bannerTimer);
  bannerTimer = setTimeout(() => $("round-banner").classList.add("hidden"), (msg.ms || BANNER_MS) - 200);
  (msg.pre || []).forEach(title => loadImage(title));
}

function showQuestion(msg) {
  const q = msg.q;
  $("round-banner").classList.add("hidden");
  view.n = msg.n;
  view.q = q;
  view.answered = false;
  view.watch = Array.isArray(msg.who) && !msg.who.includes(me());
  view.hidden = [];
  view.walkArmed = false;
  view.startedAt = Date.now();
  view.players.forEach(p => { p.done = false; });
  renderScoreboard();
  $("reveal").classList.add("hidden");
  $("reveal").replaceChildren();
  $("q-status").textContent = "";
  $("q-count").textContent = msg.count || `QUESTION ${msg.qi + 1} / ${msg.rc}`;
  const subject = E.subjectById[q.subject];
  $("q-subject").textContent = (msg.label || (subject ? subject.name : q.subject === "places" ? "Name the place" : "Name the celebrity")).toUpperCase();
  $("q-prompt").textContent = q.prompt;

  const wrap = $("q-image-wrap");
  const img = $("q-image");
  img.removeAttribute("src");
  wrap.classList.toggle("hidden", q.type !== "pic");
  if (q.type === "pic") {
    $("q-image-status").textContent = "Loading photo…";
    loadImage(q.wiki).then(url => {
      if (view.n !== msg.n) return;
      if (!url) { $("q-image-status").textContent = "Photo unavailable, take a guess!"; return; }
      img.onload = () => { $("q-image-status").textContent = ""; };
      img.onerror = () => { $("q-image-status").textContent = "Photo unavailable, take a guess!"; };
      img.src = url;
    });
  }

  const options = $("q-options");
  options.replaceChildren();
  const form = $("spell-form");
  form.classList.toggle("hidden", q.type !== "spell");
  options.classList.toggle("hidden", q.type === "spell");
  if (q.type === "spell") {
    const input = $("spell-input");
    input.value = "";
    input.disabled = false;
    $("spell-submit").disabled = false;
    $("spell-clue").textContent = speechAvailable() ? `${q.letters} letters. Type exactly what you hear.` : `${q.letters} letters. Speech isn't available on this device. Clue: ${q.clue.replace(new RegExp(q.word, "ig"), "_____")}`;
    input.focus();
    speak(q.word, q.clue);
  } else {
    stopSpeech();
    q.options.forEach((text, i) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "q-option";
      const letter = document.createElement("b");
      letter.textContent = LETTERS[i];
      button.append(letter, document.createTextNode(text));
      button.addEventListener("click", () => submit(i));
      button.disabled = view.watch;
      options.append(button);
    });
  }
  $("hint").classList.add("hidden");
  renderModeInfo(msg);
  renderLifelines();
  if (view.watch) $("q-status").textContent = msg.who.length === 1 ? `${msg.who[0]} is answering…` : "You're out of this one. Watch the others.";
  startTimer(q.secs);
}

function startTimer(secs) {
  stopTimer();
  const bar = $("timer-bar");
  const label = $("q-timer");
  const total = secs * 1000;
  bar.style.background = "";
  view.timer = setInterval(() => {
    const left = Math.max(0, total - (Date.now() - view.startedAt));
    bar.style.transform = `scaleX(${left / total})`;
    bar.style.background = left < 4000 ? "#ff6b81" : "";
    label.textContent = `${Math.ceil(left / 1000)}s`;
    if (left <= 300 && !view.answered && view.q.type === "spell" && $("spell-input").value.trim()) submit($("spell-input").value);
    if (left <= 0) stopTimer();
  }, 100);
  bar.style.transform = "scaleX(1)";
  label.textContent = `${secs}s`;
}
function stopTimer() { if (view && view.timer) { clearInterval(view.timer); view.timer = null; } }

function submit(answer) {
  if (!view || view.answered || view.watch || !view.q) return;
  if (view.q.type === "spell" && !String(answer).trim()) return;
  view.answered = true;
  renderLifelines();
  const me_ = view.players.find(p => p.n === me());
  if (me_) { me_.done = true; renderScoreboard(); }
  $("q-status").textContent = answer === -1 ? "You walked away." : view.mode === "millionaire" ? "Final answer! Waiting for the others…" : "Locked in! Waiting for the others…";
  if (view.q.type === "spell") { $("spell-input").disabled = true; $("spell-submit").disabled = true; }
  else document.querySelectorAll(".q-option").forEach((b, i) => { b.disabled = true; if (i === answer) b.classList.add("picked"); });
  if (net.role === "guest") net.hostPeer && net.hostPeer.send({ k: "ans", n: view.n, a: answer });
  else acceptAnswer(me(), view.n, answer);
}

$("spell-form").addEventListener("submit", event => { event.preventDefault(); submit($("spell-input").value); });
$("speak-button").addEventListener("click", () => { if (view && view.q && view.q.type === "spell") speak(view.q.word, view.q.clue); });
document.addEventListener("keydown", event => {
  if (screen !== "game" || !view || !view.q || view.answered || view.watch || view.q.type === "spell" || event.ctrlKey || event.metaKey || event.altKey) return;
  const index = "abcd".indexOf(event.key.toLowerCase());
  const digit = "1234".indexOf(event.key);
  const choice = index >= 0 ? index : digit;
  if (choice >= 0 && choice < (view.q.options || []).length && !view.hidden.includes(choice)) submit(choice);
});

function showReveal(msg) {
  stopTimer();
  $("timer-bar").style.transform = "scaleX(0)";
  const q = view.q;
  if (q.type === "spell") {
    $("spell-input").disabled = true;
    $("spell-submit").disabled = true;
    $("q-status").textContent = `The word was: ${msg.correct}`;
  } else {
    document.querySelectorAll(".q-option").forEach((button, i) => {
      button.disabled = true;
      const text = q.options[i];
      button.classList.toggle("right", text === msg.correct);
      const mine = msg.results.find(r => r.n === me());
      button.classList.toggle("wrong", !!mine && mine.a === text && text !== msg.correct);
    });
    $("q-status").textContent = `Answer: ${msg.correct}${msg.note ? ` · ${msg.note}` : ""}`;
  }
  const box = $("reveal");
  box.replaceChildren();
  for (const r of msg.results) {
    const row = document.createElement("div");
    row.className = "reveal-row " + (r.ok ? "ok" : "no");
    const name = document.createElement("span"); name.className = "n"; name.textContent = r.n;
    const answer = document.createElement("span"); answer.className = "a"; answer.textContent = r.a || "no answer";
    const pts = document.createElement("span"); pts.className = "p"; pts.textContent = r.t !== undefined ? r.t : r.ok ? `+${r.pts}` : "0";
    row.append(name, answer, pts);
    box.append(row);
  }
  box.classList.remove("hidden");
  msg.scores.forEach(s => { const p = view.players.find(x => x.n === s.n); if (p) { p.s = s.s; p.st = s.st; p.tag = s.tag || ""; p.done = false; } });
  renderScoreboard();
  if (msg.board) renderBoard(msg.board);
  renderLifelines();
}

function renderBoard(b) {
  const box = $("mode-info");
  box.replaceChildren();
  box.classList.remove("hidden");
  const line = document.createElement("div");
  const who = document.createElement("strong");
  who.textContent = b.name;
  line.append(who, document.createTextNode(` is playing for ${fmt(b.money)}. Get home before the Chaser catches you!`));
  const grid = document.createElement("div");
  grid.className = "board";
  for (let i = 0; i <= b.steps; i++) {
    const cell = document.createElement("div");
    cell.textContent = i === b.steps ? "🏠" : String(i + 1);
    if (i === b.steps) cell.className = "home";
    if (i === b.chaser) { cell.className = "chaser"; cell.textContent = "🕵️"; }
    if (i === b.pos && i < b.steps) { cell.className = i === b.chaser ? "chaser" : "you"; cell.textContent = i === b.chaser ? "💥" : "🙂"; }
    if (i === b.pos && i === b.steps) cell.textContent = "🙂";
    grid.append(cell);
  }
  box.append(line, grid);
}

const compactMoney = n => n >= 1000000 ? `£${n / 1000000}M` : n >= 1000 ? `£${n / 1000}K` : `£${n}`;
function renderLadder(level) {
  const box = $("mode-info");
  box.replaceChildren();
  box.classList.remove("hidden");
  const ladder = document.createElement("div");
  ladder.className = "ladder";
  E.LADDER.forEach((prize, i) => {
    const span = document.createElement("span");
    span.textContent = compactMoney(prize);
    span.className = (i < level ? "done " : i === level ? "now " : "") + (E.SAFE_AFTER.includes(i + 1) ? "safe" : "");
    ladder.append(span);
  });
  box.append(ladder);
}

function renderModeInfo(msg) {
  if (msg.board) renderBoard(msg.board);
  else if (msg.ml) renderLadder(msg.ml.level);
  else $("mode-info").classList.add("hidden");
}

function myScore() { const p = view && view.players.find(x => x.n === me()); return p ? p.s : 0; }

function renderLifelines() {
  const box = $("lifelines");
  const on = !!view && view.mode === "millionaire" && !view.watch && !!view.q;
  box.classList.toggle("hidden", !on);
  if (!on) return;
  const locked = view.answered || view.n < 0;
  document.querySelectorAll("[data-life]").forEach(button => { button.disabled = locked || !view.life[button.dataset.life]; });
  $("walk-button").disabled = locked;
  $("walk-button").textContent = view.walkArmed ? "TAP AGAIN TO WALK AWAY" : `💰 WALK AWAY (${fmt(myScore())})`;
}

function useLifeline(type) {
  if (!view || view.answered || view.watch || !view.q || !view.life[type]) return;
  view.life[type] = false;
  renderLifelines();
  if (net.role === "guest") net.hostPeer && net.hostPeer.send({ k: "life", n: view.n, t: type });
  else hostLifeline(me(), view.n, type);
}
document.querySelectorAll("[data-life]").forEach(button => button.addEventListener("click", () => useLifeline(button.dataset.life)));
$("walk-button").addEventListener("click", () => {
  if (!view || view.answered || view.watch) return;
  if (!view.walkArmed) { view.walkArmed = true; renderLifelines(); return; }
  submit(-1);
});

function showHint(msg) {
  if (!view || !view.q || msg.n !== view.n || view.answered) return;
  const box = $("hint");
  const buttons = document.querySelectorAll(".q-option");
  box.classList.remove("hidden");
  if (msg.t === "fifty") {
    view.hidden = msg.hide;
    buttons.forEach((b, i) => { if (msg.hide.includes(i)) { b.classList.add("hidden-option"); b.disabled = true; } });
    box.textContent = "50:50: two wrong answers removed.";
  } else if (msg.t === "audience") {
    buttons.forEach((b, i) => {
      if (view.hidden.includes(i)) return;
      const pct = document.createElement("span");
      pct.className = "pct";
      pct.textContent = `${msg.votes[i]}%`;
      b.append(pct);
    });
    box.textContent = "The audience has voted.";
  } else if (msg.t === "phone") {
    box.textContent = `📞 ${msg.who}: "I'm ${msg.confidence}% sure it's ${LETTERS[msg.guess]}: ${view.q.options[msg.guess]}."`;
  }
}

function showEnd(msg) {
  stopTimer();
  stopSpeech();
  const mine = msg.ranking.find(r => r.n === me());
  const stats = msg.stats[me()];
  const money = msg.mode !== "pub";
  const won = !!mine && mine.place === 1 && msg.rivals > 0 && (!money || mine.s > 0);
  const show = value => money ? fmt(value) : value.toLocaleString();
  $("result").textContent = !mine ? "Quiz over" : won ? "🏆 You won!" : msg.rivals === 0 ? `You took home ${show(mine.s)}` : `You finished #${mine.place}`;
  $("final-note").textContent = msg.note || "";
  const list = $("final-list");
  list.replaceChildren();
  for (const r of msg.ranking) {
    const row = document.createElement("div");
    row.className = "lb-row" + (r.n === me() ? " me" : "");
    const place = document.createElement("span"); place.className = "lb-place"; place.textContent = r.place <= 3 ? ["🥇", "🥈", "🥉"][r.place - 1] : `#${r.place}`;
    const name = document.createElement("span"); name.className = "lb-name"; name.textContent = r.n;
    const value = document.createElement("span"); value.className = "lb-value"; value.textContent = money ? fmt(r.s) : `${r.s.toLocaleString()} pts`;
    row.append(place, name, value);
    list.append(row);
  }
  $("game-over").classList.remove("hidden");
  if (mine && stats) {
    sdk().report("end", Object.assign({
      mode: msg.mode, score: money ? 0 : mine.s, money: money ? mine.s : 0, won, rivals: msg.rivals, online: !!msg.online,
      publicMatch: net.role === "guest" ? net.viaPublic : publicOn, allSubjects: E.SUBJECTS.map(s => s.id)
    }, stats));
  }
  view.q = null;
}

function showAbort(text) {
  stopTimer();
  stopSpeech();
  $("result").textContent = text || "The host ended the game";
  $("final-list").replaceChildren();
  $("game-over").classList.remove("hidden");
}

$("again-button").addEventListener("click", () => { hideOverlays(); view = null; showScreen("lobby"); });
$("leave-button").addEventListener("click", () => {
  stopTimer();
  stopSpeech();
  if (net.role === "guest") { leaveOnline(); return; }
  endGameEarly("The host ended the game.");
  view = null;
  showScreen("lobby");
});

// ── Text to speech (spelling) ─────────────────────────────────────────────────
const speechAvailable = () => "speechSynthesis" in window && typeof SpeechSynthesisUtterance === "function";
function stopSpeech() { if (speechAvailable()) try { speechSynthesis.cancel(); } catch (_) {} }
function speak(word, clue) {
  if (!speechAvailable()) return;
  stopSpeech();
  const voices = speechSynthesis.getVoices();
  const voice = voices.find(v => /^en[-_]GB/i.test(v.lang)) || voices.find(v => /^en/i.test(v.lang)) || null;
  // The word is said, then used in a sentence, then said once more so it is easy to catch.
  for (const [text, rate] of [[word, 0.8], [clue, 0.95], [word, 0.7]]) {
    if (!text) continue;
    const u = new SpeechSynthesisUtterance(text);
    u.rate = rate;
    if (voice) { u.voice = voice; u.lang = voice.lang; } else u.lang = "en-GB";
    speechSynthesis.speak(u);
  }
}

// ── Picture round photos ──────────────────────────────────────────────────────
// The photo comes from the article the question points to, so its name is never shown on screen.
function loadImage(title) {
  if (!images.has(title)) {
    images.set(title, fetch("https://en.wikipedia.org/api/rest_v1/page/summary/" + encodeURIComponent(title))
      .then(r => r.ok ? r.json() : null)
      .then(j => {
        const src = j && ((j.thumbnail && j.thumbnail.source) || (j.originalimage && j.originalimage.source));
        if (src) { const pre = new Image(); pre.src = src; }
        return src || null;
      })
      .catch(() => null));
    images.get(title).then(url => { if (!url) images.delete(title); });
  }
  return images.get(title);
}

// ── Achievements & leaderboard ────────────────────────────────────────────────
function renderAchievements() {
  const items = sdk().list();
  $("ach-count").textContent = `${items.filter(a => a.unlockedAt).length} / ${items.length}`;
  const list = $("ach-list");
  list.replaceChildren();
  for (const a of items) {
    const row = document.createElement("article");
    row.className = `help-card ach-row${a.unlockedAt ? " unlocked" : ""}`;
    const title = document.createElement("h3");
    title.textContent = `${a.unlockedAt ? "🏆" : a.hidden ? "❓" : "🔒"} ${a.name}`;
    const text = document.createElement("p");
    text.textContent = a.description;
    row.append(title, text);
    list.append(row);
  }
}

const lb = { metric: "wins", scope: "global", token: 0 };

async function renderLeaderboard() {
  const select = $("lb-metric");
  if (!select.options.length) for (const m of window.QZLeaderboard.METRICS) select.append(new Option(m.label, m.key));
  select.value = lb.metric;
  document.querySelectorAll("[data-scope]").forEach(b => b.classList.toggle("active", b.dataset.scope === lb.scope));
  const list = $("lb-list");
  const status = $("lb-status");
  const token = ++lb.token;
  status.textContent = "Loading…";
  list.replaceChildren();
  let board, only = null;
  try {
    board = await sdk().leaderboard();
    if (lb.scope === "friends") {
      const friends = online() ? await online().listFriends().catch(() => []) : [];
      only = new Set([...friends, sdk().user.username].map(n => n.toLowerCase()));
    }
  } catch (error) { if (token === lb.token) status.textContent = "Could not load the leaderboard."; return; }
  if (token !== lb.token) return;
  const rows = window.QZLeaderboard.rank(board, lb.metric, only);
  status.textContent = rows.length ? "" : "No scores yet. Play a quiz to get on the board!";
  const mine = sdk().user.username.toLowerCase();
  for (const r of rows.slice(0, 50)) {
    const row = document.createElement("div");
    row.className = `lb-row${r.key === mine ? " me" : ""}`;
    row.setAttribute("role", "listitem");
    const place = document.createElement("span"); place.className = "lb-place"; place.textContent = r.place <= 3 ? ["🥇", "🥈", "🥉"][r.place - 1] : `#${r.place}`;
    const name = document.createElement("span"); name.className = "lb-name"; name.textContent = r.name;
    const value = document.createElement("span"); value.className = "lb-value"; value.textContent = r.value.toLocaleString();
    row.append(place, name, value);
    list.append(row);
  }
}
$("lb-metric").addEventListener("change", event => { lb.metric = event.target.value; renderLeaderboard(); });
document.querySelectorAll("[data-scope]").forEach(button => button.addEventListener("click", () => { lb.scope = button.dataset.scope; renderLeaderboard(); }));

window.addEventListener("qz-achievement", event => {
  const a = event.detail;
  const toast = document.createElement("div");
  toast.className = "achievement-toast";
  const icon = document.createElement("div"); icon.className = "achievement-toast-icon"; icon.textContent = "🏆";
  const body = document.createElement("div");
  const head = document.createElement("strong"); head.textContent = "Achievement unlocked";
  const name = document.createElement("div"); name.textContent = a.name;
  const desc = document.createElement("small"); desc.textContent = a.description;
  body.append(head, name, desc);
  toast.append(icon, body);
  document.body.append(toast);
  setTimeout(() => toast.classList.add("show"), 20);
  setTimeout(() => { toast.classList.remove("show"); setTimeout(() => toast.remove(), 400); }, 5000);
});

// ── Online play ───────────────────────────────────────────────────────────────
async function loadFriends() {
  const select = $("friend-select");
  if (!online() || !online().supported()) { $("invite-status").textContent = "Online play needs a connection and a signed-in account. You can still play on your own."; $("invite-button").disabled = true; return; }
  if (!net.friends) {
    try { net.friends = await online().listFriends(); } catch (_) { net.friends = []; }
  }
  const previous = select.value;
  select.replaceChildren();
  if (!net.friends.length) {
    const option = document.createElement("option");
    option.textContent = "No friends yet — add some on Game OS";
    option.value = "";
    select.append(option);
  }
  for (const friend of net.friends) {
    const option = document.createElement("option");
    option.value = friend;
    option.textContent = friend;
    select.append(option);
  }
  if (previous && net.friends.includes(previous)) select.value = previous;
  $("invite-button").disabled = !net.friends.length;
}

function setInviteStatus(text) { $("invite-status").textContent = text; }

function cancelPendingInvites() {
  net.pending.forEach(handle => handle.cancel());
  net.pending = [];
}

function dropAllPeers() {
  cancelPendingInvites();
  net.peers.forEach(p => { try { p.peer.close(); } catch (_) {} });
  net.peers = [];
}

function hostCb() {
  return {
    onStatus: setInviteStatus,
    onOpen: peer => hostAcceptPeer(peer),
    onMessage: (peer, msg) => hostMessage(peer, msg),
    onClose: peer => hostDropPeer(peer),
    onFail: peer => { net.pending = net.pending.filter(h => h.peer !== peer); }
  };
}

async function setPublicOn(on) {
  if (!online() || !online().supported()) {
    publicOn = false;
    $("public").checked = false;
    $("public-status").textContent = "Public games need a connection and a signed-in account.";
    return;
  }
  $("public").disabled = true;
  try {
    await online().setPublic(on, hostCb());
    publicOn = on;
    if (on) await online().setInfo({ mode, open: true });
    $("public-status").textContent = on ? "Your lobby is listed. Anyone on Game OS can join until you start." : "";
  } catch (error) {
    publicOn = !on;
    $("public").checked = publicOn;
    $("public-status").textContent = `Could not change that: ${error.message || error}`;
  }
  $("public").disabled = false;
}

async function renderBrowse() {
  const list = $("browse-list");
  const status = $("browse-status");
  list.replaceChildren();
  if (!online() || !online().supported()) {
    status.textContent = "Online play needs a connection and a signed-in account. You can still play on your own.";
    $("quick-match").disabled = true;
    $("host-public").disabled = true;
    return;
  }
  $("quick-match").disabled = false;
  $("host-public").disabled = false;
  status.textContent = "Looking for games…";
  let rooms = [];
  try { rooms = await online().listPublic(); } catch (error) { if (screen === "browse") status.textContent = `Could not load games: ${error.message || error}`; return; }
  if (screen !== "browse") return;
  net.publicRooms = rooms;
  status.textContent = rooms.length ? "" : "No public games right now. Start one and others will find it!";
  for (const room of rooms) {
    const row = document.createElement("div");
    row.className = "browse-row";
    const info = document.createElement("span");
    const m = E.modeById[room.mode] || E.modeById[E.DEFAULT_MODE];
    info.textContent = `${m.icon} ${m.name} · ${room.host} · ${room.players}/${room.maxPlayers}`;
    const join = document.createElement("button");
    join.className = "button secondary";
    join.textContent = "JOIN";
    join.addEventListener("click", () => joinFromInvite(room.host, room.roomId, true));
    row.append(info, join);
    list.append(row);
  }
}

async function quickMatch() {
  $("quick-match").disabled = true;
  try {
    const rooms = await online().listPublic();
    const pick = rooms.find(r => r.mode === mode) || rooms[0];
    if (pick) return joinFromInvite(pick.host, pick.roomId, true);
    hostPublicGame();
  } catch (error) {
    $("browse-status").textContent = `Could not load games: ${error.message || error}`;
  } finally {
    $("quick-match").disabled = false;
  }
}

function hostPublicGame() {
  net.role = "local";
  showScreen("lobby");
  $("public").checked = true;
  setPublicOn(true);
}
$("quick-match").addEventListener("click", quickMatch);
$("host-public").addEventListener("click", hostPublicGame);
$("browse-refresh").addEventListener("click", renderBrowse);

async function inviteFriend() {
  const friend = $("friend-select").value;
  if (!friend) return;
  if (net.peers.some(p => p.name === friend) || net.pending.some(h => h.peer.friend === friend)) return setInviteStatus(`${friend} is already invited.`);
  if (net.peers.length + net.pending.length >= E.MAX_PLAYERS - 1) return setInviteStatus("The lobby is full.");
  $("invite-button").disabled = true;
  setInviteStatus(`Inviting ${friend}…`);
  try {
    const handle = await online().invite(friend, hostCb());
    net.pending.push(handle);
  } catch (error) {
    setInviteStatus(`Could not invite ${friend}: ${error.message || error}`);
  }
  $("invite-button").disabled = !net.friends || !net.friends.length;
}
$("invite-button").addEventListener("click", inviteFriend);

function hostAcceptPeer(peer) {
  net.pending = net.pending.filter(h => h.peer !== peer);
  if (screen !== "lobby" || G || net.peers.length >= E.MAX_PLAYERS - 1) { peer.send({ k: "busy" }); peer.close(); setInviteStatus(`${peer.friend} tried to join, but a game is already underway.`); return; }
  net.peers.push({ peer, name: peer.friend, subjects: [] });
  setInviteStatus(`${peer.friend} joined the lobby.`);
  peer.send({ k: "welcome", host: me() });
  broadcastLobby();
  renderLobby();
}

function hostDropPeer(peer) {
  net.pending = net.pending.filter(h => h.peer !== peer);
  const entry = net.peers.find(p => p.peer === peer);
  if (!entry) return;
  net.peers = net.peers.filter(p => p !== entry);
  if (G) {
    const player = G.players.find(p => p.name === entry.name);
    if (player) player.gone = true;
    if (G.cur) checkAllAnswered(G);
  }
  setInviteStatus(`${peer.friend} left.`);
  broadcastLobby();
  if (screen === "lobby") renderLobby();
}

function hostMessage(peer, msg) {
  const entry = net.peers.find(p => p.peer === peer);
  if (!entry || !msg) return;
  if (msg.k === "subjects" && Array.isArray(msg.list)) {
    entry.subjects = msg.list.filter(id => typeof id === "string" && E.subjectById[id]).slice(0, E.MAX_SUBJECTS);
    broadcastLobby();
    if (screen === "lobby") renderLobby();
  } else if (msg.k === "ans") acceptAnswer(entry.name, msg.n, msg.a);
  else if (msg.k === "life") hostLifeline(entry.name, msg.n, msg.t);
  else if (msg.k === "bye") peer.close();
}

function setJoinStatus(text) { $("join-status").textContent = text; }

function leaveOnline() {
  if (net.hostPeer) { net.hostPeer.send({ k: "bye" }); net.hostPeer.close(); }
  net.hostPeer = null;
  net.role = "local";
  net.lobby = [];
  view = null;
  hideOverlays();
  showScreen("menu");
}

function guestMessage(msg) {
  if (!msg) return;
  if (msg.k === "welcome") {
    net.hostName = msg.host;
    net.role = "guest";
    net.hostPeer.send({ k: "subjects", list: mySubjects });
    showScreen("lobby");
  } else if (msg.k === "busy") setJoinStatus("The host is already in a game. Ask them to invite you again.");
  else if (msg.k === "lobby") { net.lobby = msg.players; if (E.modeById[msg.mode]) net.lobbyMode = msg.mode; if (screen === "lobby") renderLobby(); }
  else onMessage(msg);
}

async function joinFromInvite(host, roomId, viaPublic) {
  showScreen("join");
  net.viaPublic = !!viaPublic;
  setJoinStatus(`Joining ${host}…`);
  try {
    net.hostPeer = await online().join(host, roomId, {
      onStatus: setJoinStatus,
      onMessage: (_peer, msg) => guestMessage(msg),
      onClose: () => {
        if (!net.hostPeer) return;
        net.hostPeer = null;
        net.role = "local";
        view = null;
        hideOverlays();
        stopTimer();
        $("join-leave").textContent = "← BACK TO MENU";
        setJoinStatus(`${host} closed the lobby.`);
        showScreen("join");
      }
    });
    setJoinStatus(`Connected to ${host}. Waiting for the lobby…`);
  } catch (error) {
    setJoinStatus(error.message || String(error));
  }
}
$("join-leave").addEventListener("click", () => { if (net.hostPeer) leaveOnline(); else { net.role = "local"; showScreen("menu"); } });
window.addEventListener("pagehide", () => { if (net.hostPeer) net.hostPeer.send({ k: "bye" }); });

// ── Boot: Game OS sign-in + licence check, then the game ──────────────────────
(async function start() {
  const session = await sdk().boot();
  if (!session) return;
  loadWeekly();
  renderLobby();
  const params = new URLSearchParams(location.search);
  if (params.get("join") && params.get("room")) {
    history.replaceState(null, "", location.pathname + (sdk().isDesktop ? "?client=desktop" : ""));
    joinFromInvite(params.get("join"), params.get("room"));
  }
})();
})();
