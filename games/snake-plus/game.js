(function () {
"use strict";

const WIDTH = 51;
const HEIGHT = 28;
const CELL = 25;
const TICK = 16;
const TYPES = [
  ["none", "OFF"], ["keyboard", "HUMAN (KEYBOARD)"], ["gamepad", "HUMAN (GAMEPAD)"],
  ["easy", "BOT (EASY)"], ["normal", "BOT (NORMAL)"], ["hard", "BOT (HARD)"]
];
const REMOTE_TYPE = ["remote", "ONLINE FRIEND"];
const SNAPSHOT_EVERY = 3;
const MAX_BUFFERED = 256 * 1024;
const sdk = () => window.GameOSSDK;
const online = () => window.SnakeOnline;
const COLORS = [
  { name: "RED", value: "#f36b57" }, { name: "GREEN", value: "#b9ef4f" },
  { name: "BLUE", value: "#68aef5" }, { name: "ORANGE", value: "#f8a052" }
];
const UNLOCKS = [
  [{ name: "CRIMSON", value: "#dc143c" }, { name: "DARK RED", value: "#9b3030" }],
  [{ name: "LIME GREEN", value: "#32cd32" }, { name: "SPRING GREEN", value: "#00fa9a" }],
  [{ name: "DODGER BLUE", value: "#1e90ff" }, { name: "DEEP SKY BLUE", value: "#00bfff" }],
  [{ name: "DARK ORANGE", value: "#ff8c00" }, { name: "GOLD", value: "#ffd700" }]
];
const MODES = {
  survival: ["SURVIVAL", "Last snake standing wins. Flying solo? See how long you can survive."],
  firstTo: ["FIRST TO", "The first snake to reach the target score takes the win."],
  classic: ["CLASSIC 1P", "Just you and the board. Survive and grow your score."],
  rush: ["RUSH", "Last snake standing wins. The longer you get, the faster you go."]
};
const DIRECTIONS = { up: [0, -1], down: [0, 1], left: [-1, 0], right: [1, 0] };
const ITEM_COLORS = { food: "#f36b57", speed: "#62e1e4", lockdown: "#ae3c38", colour: "#e272df", tp: "#f4df58", destruction: "#ff854e", bomb: "#858b83" };
const $ = id => document.getElementById(id);
const canvas = $("board");
const ctx = canvas.getContext("2d");
let wins = [0, 0, 0, 0];
try {
  const saved = JSON.parse(localStorage.getItem("snake-plus-wins") || "null");
  if (Array.isArray(saved)) wins = wins.map((_, i) => Number.isSafeInteger(saved[i]) && saved[i] >= 0 ? saved[i] : 0);
} catch (error) {
  console.warn("Could not load saved wins:", error);
}
const players = COLORS.map((color, index) => ({
  index, color, type: index === 0 ? "keyboard" : "none", body: [], alive: false, label: "",
  direction: [1, 0], nextDirection: [1, 0], speed: 0, destruction: 0
}));
// Online play: "host" runs the simulation and streams snapshots, "client" only renders them and sends steering.
const net = { role: "local", hostPeers: [], pending: [], hostPeer: null, you: -1, friends: null };
let screen = "menu";
let mode = "survival";
let target = 50;
let items = [];
let effects = [];
let lockdown = 0;
let tick = 0;
let lastFrame = 0;
let accumulator = 0;
let previousButtons = [];

function showScreen(name) {
  screen = name;
  for (const id of ["menu", "lobby", "help", "game", "join", "achievements", "leaderboard"]) $(id).classList.toggle("hidden", id !== name);
  if (sdk()) sdk().setRunning(name === "game");
  if (name === "lobby") { renderLobby(); loadFriends(); }
  if (name === "achievements") renderAchievements();
  if (name === "leaderboard") renderLeaderboard();
  if (name === "menu") { cancelPendingInvites(); if (online()) online().closeRoom(); }
  window.scrollTo(0, 0);
}

function colorPool(player) {
  return wins[player.index] > 0 ? COLORS.concat(UNLOCKS[player.index]) : COLORS;
}

function cycleColor(player, includeCurrent = false) {
  const pool = colorPool(player);
  const current = pool.findIndex(color => color.value === player.color.value);
  for (let offset = includeCurrent ? 0 : 1; offset < pool.length + (includeCurrent ? 0 : 1); offset++) {
    const color = pool[(Math.max(current, 0) + offset) % pool.length];
    if (!players.some(other => other !== player && other.type !== "none" && other.color.value === color.value)) {
      player.color = color;
      return;
    }
  }
}

function renderLobby() {
  const container = $("player-slots");
  container.replaceChildren();
  players.forEach(player => {
    const card = document.createElement("article");
    card.className = "player-card";
    const heading = document.createElement("div");
    heading.className = "slot-heading";
    const title = document.createElement("strong");
    title.textContent = `PLAYER 0${player.index + 1}${player.type === "remote" ? " / " + player.label.toUpperCase() : ""}`;
    const winLabel = document.createElement("span");
    winLabel.className = "slot-meta";
    winLabel.textContent = `${wins[player.index]} WINS`;
    heading.append(title, winLabel);
    const label = document.createElement("label");
    label.htmlFor = `player-${player.index}`;
    label.textContent = "PLAYER TYPE";
    const select = document.createElement("select");
    select.id = label.htmlFor;
    for (const [value, text] of player.type === "remote" ? TYPES.concat([REMOTE_TYPE]) : TYPES) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = text;
      select.append(option);
    }
    select.value = player.type;
    select.disabled = player.type === "remote";
    select.addEventListener("change", () => {
      const wasOff = player.type === "none";
      player.type = select.value;
      if (wasOff && player.type !== "none") cycleColor(player, true);
      renderLobby();
      $(`player-${player.index}`).focus();
    });
    const color = document.createElement("button");
    color.type = "button";
    color.className = "color-button";
    color.disabled = player.type === "none";
    const dot = document.createElement("span");
    dot.className = "slot-color";
    dot.style.backgroundColor = player.color.value;
    color.append(dot, document.createTextNode(player.type === "none" ? "SLOT INACTIVE" : `${player.color.name} / CHANGE COLOR ↗`));
    color.addEventListener("click", () => {
      cycleColor(player);
      renderLobby();
      container.children[player.index].querySelector(".color-button").focus();
    });
    card.append(heading, label, select, color);
    container.append(card);
  });
  $("mode").value = mode;
  $("mode-description").textContent = MODES[mode][1];
  $("target-wrap").classList.toggle("hidden", mode !== "firstTo");
  $("lobby-error").textContent = "";
}

function startGame() {
  if (net.role === "client" || !sdk() || !sdk().state) return;
  const active = players.filter(p => p.type !== "none");
  const rawTarget = Number($("target").value);
  if (!active.length) return $("lobby-error").textContent = "Choose at least one player to start.";
  if (active.filter(p => p.type === "keyboard").length > 1) return $("lobby-error").textContent = "Choose only one keyboard player; use gamepads or bots for the other slots.";
  if (mode === "classic" && active.length !== 1) return $("lobby-error").textContent = "Classic 1P requires exactly one active player.";
  if (mode === "firstTo" && (!Number.isSafeInteger(rawTarget) || rawTarget < 50 || rawTarget % 50 !== 0)) return $("lobby-error").textContent = "Choose a target score in increments of 50.";
  target = rawTarget;
  const spawns = [[10, 10], [WIDTH - 10, HEIGHT - 10], [10, HEIGHT - 10], [WIDTH - 10, 10]];
  const dirs = [[1, 0], [-1, 0], [1, 0], [-1, 0]];
  players.forEach(p => {
    p.alive = p.type !== "none";
    p.body = p.alive ? Array.from({ length: 3 }, (_, j) => [spawns[p.index][0] - j * dirs[p.index][0], spawns[p.index][1]]) : [];
    p.direction = [...dirs[p.index]];
    p.nextDirection = [...p.direction];
    p.speed = p.destruction = 0;
  });
  items = [];
  effects = [];
  tick = lockdown = 0;
  accumulator = 0;
  spawnItem("food");
  $("game-mode-label").textContent = MODES[mode][0];
  $("game-over").classList.add("hidden");
  net.role = net.hostPeers.length ? "host" : "local";
  net.hostPeers.forEach(({ peer, slot }) => peer.send({ t: "start", mode, target, you: slot }));
  const localHuman = localPlayer();
  if (localHuman) sdk().report("start", { online: net.role === "host" });
  showScreen("game");
  renderGame();
}

function localPlayer() { return players.find(p => p.type === "keyboard") || players.find(p => p.type === "gamepad"); }

function same(a, b) { return a[0] === b[0] && a[1] === b[1]; }
function randomItem(array) { return array[Math.floor(Math.random() * array.length)]; }
function spawnItem(type) {
  const free = [];
  for (let y = 1; y < HEIGHT - 1; y++) for (let x = 1; x < WIDTH - 1; x++) {
    const point = [x, y];
    if (x === Math.floor(WIDTH / 2) || y === Math.floor(HEIGHT / 2)) continue;
    if (players.some(p => p.alive && p.body.some(segment => same(segment, point)))) continue;
    if (items.some(item => same(item.position, point))) continue;
    free.push(point);
  }
  if (free.length) items.push({ type, position: randomItem(free) });
}
function setDirection(player, direction) {
  if (player && player.alive && direction[0] !== -player.direction[0] && direction[1] !== -player.direction[1]) player.nextDirection = direction;
}
function botMove(bot) {
  const head = bot.body[0];
  const safe = Object.values(DIRECTIONS).filter(dir => {
    if (dir[0] === -bot.direction[0] && dir[1] === -bot.direction[1]) return false;
    const next = [head[0] + dir[0], head[1] + dir[1]];
    return next[0] >= 0 && next[0] < WIDTH && next[1] >= 0 && next[1] < HEIGHT &&
      !(lockdown && (next[0] === Math.floor(WIDTH / 2) || next[1] === Math.floor(HEIGHT / 2))) &&
      !players.some(p => p.alive && p.body.some(segment => same(segment, next)));
  });
  if (!safe.length) return;
  let choice = randomItem(safe);
  const threshold = { easy: 0.3, normal: 0.75, hard: 1 }[bot.type];
  if (items.length && Math.random() < threshold) {
    const distance = (a, b) => Math.abs(a[0] - b[0]) + Math.abs(a[1] - b[1]);
    const item = items.reduce((best, next) => distance(next.position, head) < distance(best.position, head) ? next : best);
    choice = safe.reduce((best, next) => distance([head[0] + next[0], head[1] + next[1]], item.position) < distance([head[0] + best[0], head[1] + best[1]], item.position) ? next : best);
  }
  bot.nextDirection = choice;
}

function applyItem(player, item) {
  const rivals = players.filter(p => p.alive && p !== player);
  let message = "+5 POINTS";
  if (item.type === "food") spawnItem("food");
  if (item.type === "speed") { player.speed = 300; message = "SPEED UP!"; }
  if (item.type === "lockdown") { lockdown = 1200; message = "LOCKDOWN!"; }
  if (item.type === "destruction") { player.destruction = 300; message = "DESTRUCTION!"; }
  if (item.type === "bomb") { player.alive = false; message = "BOOM!"; }
  if (item.type === "colour") {
    message = "COLOR SWAP!";
    if (rivals.length) {
      const rival = randomItem(rivals);
      [player.color, rival.color] = [rival.color, player.color];
      const length = player.body.length;
      const rivalLength = rival.body.length;
      while (player.body.length < rivalLength) player.body.push([...player.body[player.body.length - 1]]);
      while (rival.body.length < length) rival.body.push([...rival.body[rival.body.length - 1]]);
      player.body.length = rivalLength;
      rival.body.length = length;
    }
  }
  if (item.type === "tp") {
    message = "TELEPORT!";
    if (rivals.length) {
      const rival = randomItem(rivals);
      [player.body, rival.body] = [rival.body, player.body];
      [player.direction, rival.direction] = [rival.direction, player.direction];
      [player.nextDirection, rival.nextDirection] = [rival.nextDirection, player.nextDirection];
    }
  }
  effects.push({ text: message, x: item.position[0], y: item.position[1], time: 60, color: ITEM_COLORS[item.type] });
  notify(player, "item", { item: item.type });
}

/** Achievement events: local humans report directly, online friends get theirs over the channel. */
function notify(player, type, ctx) {
  if (net.role === "client") return;
  if (player.type === "keyboard" || player.type === "gamepad") { if (player === localPlayer()) sdk().report(type, ctx); }
  else if (player.type === "remote") {
    const entry = net.hostPeers.find(h => h.slot === player.index);
    if (entry) entry.peer.send({ t: "ev", type, ctx });
  }
}

function updateGame() {
  tick++;
  for (const player of players) {
    if (!player.alive) continue;
    if (["easy", "normal", "hard"].includes(player.type) && tick % 6 === 0) botMove(player);
    let rate = mode === "rush" ? Math.max(2, 6 - Math.floor(player.body.length / 3)) : 6;
    if (player.speed > 0) rate = Math.max(1, Math.floor(rate / 2));
    if (tick % rate === 0) {
      player.direction = player.nextDirection;
      const next = [player.body[0][0] + player.direction[0], player.body[0][1] + player.direction[1]];
      if (next[0] < 0 || next[0] >= WIDTH || next[1] < 0 || next[1] >= HEIGHT ||
          (lockdown && (next[0] === Math.floor(WIDTH / 2) || next[1] === Math.floor(HEIGHT / 2)))) {
        player.alive = false;
        continue;
      }
      let crashed = false;
      for (const other of players.filter(p => p.alive)) {
        const hit = other.body.findIndex((segment, i) => (other !== player || i > 0) && same(segment, next));
        if (hit < 0) continue;
        if (other !== player && hit > 0 && player.destruction > 0) {
          const removed = other.body.length - hit;
          other.body.length = hit;
          effects.push({ text: `CHOPPED -${removed * 5} PTS`, x: next[0], y: next[1], time: 60, color: "#f36b57" });
          notify(player, "chop", {});
        } else crashed = true;
      }
      if (crashed) { player.alive = false; continue; }
      player.body.unshift(next);
      const itemIndex = items.findIndex(item => same(item.position, next));
      if (itemIndex >= 0) applyItem(player, items.splice(itemIndex, 1)[0]);
      else player.body.pop();
    }
    if (player.speed > 0) player.speed--;
    if (player.destruction > 0) player.destruction--;
  }
  if (lockdown > 0) lockdown--;
  effects.forEach(effect => { effect.time--; effect.y -= 0.032; });
  effects = effects.filter(effect => effect.time > 0);
  if (tick % 300 === 0 && items.length < 4) {
    const chance = Math.random() * 100;
    spawnItem(chance < 12 ? "lockdown" : chance < 24 ? "bomb" : chance < 38 ? "colour" : chance < 52 ? "tp" : chance < 66 ? "destruction" : chance < 84 ? "speed" : "food");
  }
  checkWin();
  if (screen === "game" && net.role === "host" && tick % SNAPSHOT_EVERY === 0) broadcastSnapshot();
}

function checkWin() {
  const active = players.filter(p => p.type !== "none");
  const alive = active.filter(p => p.alive);
  if (mode === "classic") {
    if (!alive.length) endGame(`GAME OVER! SCORE: ${active[0].body.length * 5}`);
  } else if (mode === "firstTo") {
    const winner = active.find(p => p.body.length * 5 >= target);
    if (winner) endGame(`PLAYER ${winner.index + 1} REACHED ${target} POINTS!`, winner);
    else if (!alive.length) endGame("DRAW! EVERYONE DIED.");
  } else if (alive.length === 1 && active.length > 1) {
    endGame(`PLAYER ${alive[0].index + 1} WINS ${MODES[mode][0]}!`, alive[0]);
  } else if (!alive.length) {
    endGame(mode === "rush" ? `RUSH OVER! BEST SCORE: ${Math.max(...active.map(p => p.body.length * 5))}` : active.length === 1 ? `GAME OVER! SCORE: ${active[0].body.length * 5}` : "DRAW! EVERYONE DIED.");
  }
}

function endContext(player, winner) {
  const active = players.filter(p => p.type !== "none");
  return {
    mode, score: player.body.length * 5, won: winner === player, online: active.some(p => p.type === "remote"),
    rivals: active.filter(p => p !== player).map(p => p.type), ticks: tick, died: !player.alive
  };
}

function endGame(message, winner) {
  screen = "gameover";
  sdk().setRunning(false);
  $("result").textContent = message;
  $("game-over").classList.remove("hidden");
  if (net.role === "host") {
    broadcastSnapshot();
    net.hostPeers.forEach(({ peer, slot }) => peer.send({ t: "over", msg: message, w: winner ? winner.index : -1, r: endContext(players[slot], winner) }));
  }
  const mine = localPlayer();
  if (mine) sdk().report("end", endContext(mine, winner));
  if (winner && ["keyboard", "gamepad"].includes(winner.type)) {
    wins[winner.index]++;
    try { localStorage.setItem("snake-plus-wins", JSON.stringify(wins)); }
    catch (error) { console.warn("Could not save wins:", error); }
  }
}

function renderGame() {
  ctx.fillStyle = "#121b12";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = "#1c2a1c";
  ctx.lineWidth = 1;
  for (let x = 0; x <= WIDTH; x++) { ctx.beginPath(); ctx.moveTo(x * CELL, 0); ctx.lineTo(x * CELL, canvas.height); ctx.stroke(); }
  for (let y = 0; y <= HEIGHT; y++) { ctx.beginPath(); ctx.moveTo(0, y * CELL); ctx.lineTo(canvas.width, y * CELL); ctx.stroke(); }
  if (lockdown) {
    ctx.fillStyle = "#a93c38";
    ctx.fillRect(Math.floor(WIDTH / 2) * CELL, 0, CELL, canvas.height);
    ctx.fillRect(0, Math.floor(HEIGHT / 2) * CELL, canvas.width, CELL);
  }
  for (const item of items) {
    const [x, y] = item.position.map(n => n * CELL);
    ctx.fillStyle = ITEM_COLORS[item.type];
    if (item.type === "food" || item.type === "bomb") {
      ctx.beginPath(); ctx.arc(x + CELL / 2, y + CELL / 2, CELL / 2 - 2, 0, Math.PI * 2); ctx.fill();
    } else ctx.fillRect(x + 2, y + 2, CELL - 4, CELL - 4);
    if (item.type === "bomb" || item.type === "lockdown") {
      ctx.fillStyle = "#fff"; ctx.font = "bold 16px sans-serif"; ctx.textAlign = "center";
      ctx.fillText(item.type === "bomb" ? "B" : "X", x + CELL / 2, y + 18);
    }
  }
  for (const player of players) {
    ctx.globalAlpha = player.alive ? 1 : 0.25;
    ctx.fillStyle = player.color.value;
    player.body.forEach(([x, y]) => ctx.fillRect(x * CELL + 1, y * CELL + 1, CELL - 2, CELL - 2));
    if (player.alive && (player.speed || player.destruction)) {
      ctx.strokeStyle = player.destruction ? ITEM_COLORS.destruction : ITEM_COLORS.speed;
      ctx.lineWidth = 3;
      ctx.strokeRect(player.body[0][0] * CELL + 2, player.body[0][1] * CELL + 2, CELL - 4, CELL - 4);
    }
  }
  ctx.globalAlpha = 1;
  for (const effect of effects) {
    ctx.globalAlpha = effect.time / 60;
    ctx.fillStyle = effect.color;
    ctx.font = "bold 18px sans-serif";
    ctx.textAlign = "left";
    ctx.fillText(effect.text, effect.x * CELL, effect.y * CELL);
  }
  ctx.globalAlpha = 1;
  const scoreboard = $("scoreboard");
  scoreboard.replaceChildren();
  players.filter(p => p.type !== "none").forEach(player => {
    const score = document.createElement("div");
    score.className = `score${player.alive ? "" : " dead"}`;
    const dot = document.createElement("span");
    dot.className = "slot-color";
    dot.style.backgroundColor = player.color.value;
    score.append(dot, document.createTextNode(`P${player.index + 1}${player.label ? " " + player.label.toUpperCase() : ""} / ${player.color.name}${player.destruction ? " / DESTRUCT" : ""}`));
    const value = document.createElement("strong");
    value.textContent = player.body.length * 5;
    score.append(value);
    scoreboard.append(score);
  });
  $("game-status").textContent = lockdown ? "LOCKDOWN ACTIVE — AVOID THE CENTER" : "STAY SHARP. KEEP MOVING.";
}

function navigateGamepad(pressed) {
  const controls = Array.from(document.querySelectorAll(`#${screen} button:not(:disabled), #${screen} select, #${screen} input:not(.hidden)`))
    .filter(element => element.getClientRects().length);
  const selected = controls.indexOf(document.activeElement);
  if ((pressed(12) || pressed(13)) && controls.length) {
    const step = pressed(12) ? -1 : 1;
    controls[selected < 0 ? 0 : (selected + step + controls.length) % controls.length].focus();
  }
  const focused = document.activeElement;
  if ((pressed(14) || pressed(15)) && focused instanceof HTMLSelectElement && controls.includes(focused)) {
    const step = pressed(14) ? -1 : 1;
    focused.selectedIndex = (focused.selectedIndex + step + focused.options.length) % focused.options.length;
    focused.dispatchEvent(new Event("change", { bubbles: true }));
  } else if ((pressed(14) || pressed(15)) && focused instanceof HTMLInputElement && focused.type === "number") {
    if (pressed(14)) focused.stepDown(); else focused.stepUp();
  }
  if (pressed(0) && controls.includes(focused) && focused instanceof HTMLButtonElement) focused.click();
}

function pollGamepads() {
  if (!navigator.getGamepads) return;
  const pads = Array.from(navigator.getGamepads()).filter(Boolean);
  pads.forEach((pad, index) => {
    const previous = previousButtons[pad.index] || [];
    const pressed = button => pad.buttons[button]?.pressed && !previous[button];
    if (screen === "game") {
      const player = players.filter(p => p.type === "gamepad")[index];
      for (const [button, direction] of [[12, "up"], [13, "down"], [14, "left"], [15, "right"]]) {
        if (pressed(button)) steer(DIRECTIONS[direction], player);
      }
    } else if (screen === "gameover" && (pressed(0) || pressed(1) || pressed(9))) afterGame();
    else if (screen === "lobby" && pressed(9)) startGame();
    else if ((screen === "lobby" || screen === "help") && pressed(1)) showScreen("menu");
    else if (screen === "menu" || screen === "lobby" || screen === "help") {
      if (screen === "menu" && (pressed(0) || pressed(9)) && !document.activeElement.closest("#menu")) showScreen("lobby");
      else navigateGamepad(pressed);
    }
    previousButtons[pad.index] = pad.buttons.map(button => button.pressed);
  });
  const connected = new Set(pads.map(pad => pad.index));
  previousButtons = previousButtons.map((buttons, index) => connected.has(index) ? buttons : undefined);
}

function frame(time) {
  pollGamepads();
  if (screen === "game") {
    if (net.role !== "client") {
      accumulator += Math.min(time - (lastFrame || time), 100);
      while (accumulator >= TICK && screen === "game") { updateGame(); accumulator -= TICK; }
    }
    renderGame();
  } else accumulator = 0;
  lastFrame = time;
  requestAnimationFrame(frame);
}

$("play-button").addEventListener("click", () => showScreen("lobby"));
$("how-button").addEventListener("click", () => showScreen("help"));
document.querySelectorAll("[data-go]").forEach(button => button.addEventListener("click", () => showScreen(button.dataset.go)));
$("start-button").addEventListener("click", startGame);
$("leave-button").addEventListener("click", leaveGame);
$("again-button").addEventListener("click", afterGame);
$("mode").addEventListener("change", event => { mode = event.target.value; renderLobby(); $("mode").focus(); });
document.querySelectorAll("[data-direction]").forEach(button => button.addEventListener("click", () => steer(DIRECTIONS[button.dataset.direction])));
document.addEventListener("keydown", event => {
  if (screen === "game") {
    const key = event.key.toLowerCase();
    const direction = { arrowup: "up", w: "up", arrowdown: "down", s: "down", arrowleft: "left", a: "left", arrowright: "right", d: "right" }[key];
    if (direction) { event.preventDefault(); steer(DIRECTIONS[direction]); }
  } else if (screen === "gameover" && ["Enter", " ", "Escape"].includes(event.key)) {
    event.preventDefault(); afterGame();
  } else if ((screen === "help" || screen === "achievements" || screen === "leaderboard") && event.key === "Escape") showScreen("menu");
});

function steer(direction, player) {
  if (net.role === "client") { if (net.hostPeer) net.hostPeer.send({ t: "dir", d: direction }); return; }
  setDirection(player || players.find(p => p.type === "keyboard"), direction);
}

function afterGame() { showScreen(net.role === "client" ? "join" : "lobby"); }

function leaveGame() {
  if (net.role === "client") return leaveOnline();
  if (net.role === "host") net.hostPeers.forEach(({ peer }) => peer.send({ t: "over", msg: "THE HOST ENDED THE GAME", w: -1, r: null }));
  showScreen("lobby");
}

// ── Achievements ──────────────────────────────────────────────────────────────
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
  if (!select.options.length) {
    for (const m of window.SPLeaderboard.METRICS) select.append(new Option(m.label, m.key));
  }
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
  const rows = window.SPLeaderboard.rank(board, lb.metric, only);
  status.textContent = rows.length ? "" : "No scores yet. Play a match to get on the board!";
  const me = sdk().user.username.toLowerCase();
  for (const r of rows.slice(0, 50)) {
    const row = document.createElement("div");
    row.className = `lb-row${r.key === me ? " me" : ""}`;
    row.setAttribute("role", "listitem");
    const place = document.createElement("span");
    place.className = "lb-place";
    place.textContent = r.place <= 3 ? ["🥇", "🥈", "🥉"][r.place - 1] : `#${r.place}`;
    const name = document.createElement("span");
    name.className = "lb-name";
    name.textContent = r.name;
    const value = document.createElement("span");
    value.className = "lb-value";
    value.textContent = r.value.toLocaleString();
    row.append(place, name, value);
    list.append(row);
  }
}

$("lb-metric").addEventListener("change", event => { lb.metric = event.target.value; renderLeaderboard(); });
document.querySelectorAll("[data-scope]").forEach(button => button.addEventListener("click", () => { lb.scope = button.dataset.scope; renderLeaderboard(); }));

window.addEventListener("sp-achievement", event => {
  const a = event.detail;
  const toast = document.createElement("div");
  toast.className = "achievement-toast";
  const icon = document.createElement("div");
  icon.className = "achievement-toast-icon";
  icon.textContent = "🏆";
  const body = document.createElement("div");
  const head = document.createElement("strong");
  head.textContent = "Achievement unlocked";
  const name = document.createElement("div");
  name.textContent = a.name;
  const desc = document.createElement("small");
  desc.textContent = a.description;
  body.append(head, name, desc);
  toast.append(icon, body);
  document.body.append(toast);
  setTimeout(() => toast.classList.add("show"), 20);
  setTimeout(() => { toast.classList.remove("show"); setTimeout(() => toast.remove(), 400); }, 5000);
});

// ── Online play ───────────────────────────────────────────────────────────────
async function loadFriends() {
  const select = $("friend-select");
  if (!online() || !online().supported()) { $("invite-status").textContent = "Online play isn't supported on this device."; $("invite-button").disabled = true; return; }
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

function freeSlot() { return players.find(p => p.type === "none"); }

async function inviteFriend() {
  const friend = $("friend-select").value;
  if (!friend) return;
  if (net.hostPeers.some(h => h.peer.friend === friend) || net.pending.some(h => h.peer.friend === friend)) return setInviteStatus(`${friend} is already invited.`);
  if (net.hostPeers.length + net.pending.length >= players.filter(p => p.type === "none" || p.type === "remote").length) return setInviteStatus("No free player slot. Set a slot to OFF first.");
  $("invite-button").disabled = true;
  setInviteStatus(`Inviting ${friend}…`);
  try {
    const handle = await online().invite(friend, {
      onStatus: setInviteStatus,
      onOpen: peer => hostAcceptPeer(peer),
      onMessage: (peer, msg) => hostMessage(peer, msg),
      onClose: peer => hostDropPeer(peer),
      onFail: peer => { net.pending = net.pending.filter(h => h.peer !== peer); }
    });
    net.pending.push(handle);
  } catch (error) {
    setInviteStatus(`Could not invite ${friend}: ${error.message || error}`);
  }
  $("invite-button").disabled = !net.friends.length;
}

function hostAcceptPeer(peer) {
  net.pending = net.pending.filter(h => h.peer !== peer);
  const slot = screen === "lobby" ? freeSlot() : null;
  if (!slot) { peer.send({ t: "busy" }); peer.close(); setInviteStatus(`${peer.friend} tried to join, but a game is already underway.`); return; }
  slot.type = "remote";
  slot.label = peer.friend;
  cycleColor(slot, true);
  net.hostPeers.push({ peer, slot: slot.index });
  setInviteStatus(`${peer.friend} joined as Player ${slot.index + 1}.`);
  peer.send({ t: "hello", you: slot.index, host: sdk().user.username });
  renderLobby();
}

function hostDropPeer(peer) {
  net.pending = net.pending.filter(h => h.peer !== peer);
  const entry = net.hostPeers.find(h => h.peer === peer);
  if (!entry) return;
  net.hostPeers = net.hostPeers.filter(h => h !== entry);
  const player = players[entry.slot];
  if (screen === "game") player.alive = false;
  player.type = "none";
  player.label = "";
  setInviteStatus(`${peer.friend} left.`);
  if (screen === "lobby") renderLobby();
}

function hostMessage(peer, msg) {
  const entry = net.hostPeers.find(h => h.peer === peer);
  if (!entry || !msg) return;
  if (msg.t === "dir" && Array.isArray(msg.d) && Object.values(DIRECTIONS).some(d => d[0] === msg.d[0] && d[1] === msg.d[1])) {
    if (screen === "game") setDirection(players[entry.slot], msg.d);
  } else if (msg.t === "bye") peer.close();
}

function broadcastSnapshot() {
  const ready = net.hostPeers.filter(h => h.peer.open);
  if (!ready.length) return;
  const snapshot = {
    t: "s", l: lockdown, i: items, e: effects,
    p: players.map(p => ({ y: p.type, c: p.color, b: p.body, a: p.alive ? 1 : 0, s: p.speed, d: p.destruction, n: p.label || (p.type === "keyboard" || p.type === "gamepad" ? sdk().user.username : "") }))
  };
  ready.forEach(({ peer }) => peer.send(snapshot));
}

function applySnapshot(s) {
  lockdown = s.l;
  items = s.i;
  effects = s.e;
  s.p.forEach((data, i) => {
    const p = players[i];
    p.type = data.y; p.color = data.c; p.body = data.b; p.alive = !!data.a; p.speed = data.s; p.destruction = data.d; p.label = data.n;
  });
}

function setJoinStatus(text) { $("join-status").textContent = text; }

function leaveOnline() {
  if (net.hostPeer) { net.hostPeer.send({ t: "bye" }); net.hostPeer.close(); }
  net.hostPeer = null;
  net.role = "local";
  net.you = -1;
  players.forEach((p, i) => { p.type = i === 0 ? "keyboard" : "none"; p.label = ""; });
  showScreen("menu");
}

function clientMessage(msg) {
  if (!msg) return;
  if (msg.t === "hello") setJoinStatus(`Connected to ${msg.host}. Waiting for the host to start the game…`);
  else if (msg.t === "busy") { setJoinStatus("The host is already in a game. Ask them to invite you again."); }
  else if (msg.t === "start") {
    net.role = "client";
    net.you = msg.you;
    mode = msg.mode;
    target = msg.target;
    $("game-mode-label").textContent = `${MODES[mode][0]} / ONLINE`;
    $("game-over").classList.add("hidden");
    sdk().report("start", { online: true });
    showScreen("game");
  } else if (msg.t === "s" && net.role === "client") {
    applySnapshot(msg);
    if (screen === "game") renderGame();
  } else if (msg.t === "ev") sdk().report(msg.type, msg.ctx);
  else if (msg.t === "over") {
    if (screen !== "game") return;
    screen = "gameover";
    sdk().setRunning(false);
    $("result").textContent = msg.msg;
    $("game-over").classList.remove("hidden");
    if (msg.r) sdk().report("end", msg.r);
    if (msg.w === net.you && msg.w >= 0) {
      wins[net.you]++;
      try { localStorage.setItem("snake-plus-wins", JSON.stringify(wins)); } catch (error) { console.warn("Could not save wins:", error); }
    }
    renderGame();
  }
}

async function joinFromInvite(host, roomId) {
  showScreen("join");
  setJoinStatus(`Joining ${host}…`);
  try {
    net.hostPeer = await online().join(host, roomId, {
      onStatus: setJoinStatus,
      onMessage: (_peer, msg) => clientMessage(msg),
      onClose: () => {
        if (!net.hostPeer) return;
        net.hostPeer = null;
        net.role = "local";
        players.forEach((p, i) => { p.type = i === 0 ? "keyboard" : "none"; p.label = ""; });
        $("join-leave").textContent = "← BACK TO MENU";
        setJoinStatus(`${host} closed the lobby.`);
        showScreen("join");
      }
    });
    net.role = "client";
    setJoinStatus(`Connected to ${host}. Waiting for the host to start the game…`);
  } catch (error) {
    setJoinStatus(error.message || String(error));
  }
}

$("invite-button").addEventListener("click", inviteFriend);
$("join-leave").addEventListener("click", () => { if (net.hostPeer) leaveOnline(); else { net.role = "local"; showScreen("menu"); } });
window.addEventListener("pagehide", () => { if (net.hostPeer) net.hostPeer.send({ t: "bye" }); });

// ── Boot: Game OS sign-in + licence check, then the game ──────────────────────
(async function start() {
  const session = await sdk().boot();
  if (!session) return;
  const params = new URLSearchParams(location.search);
  if (params.get("join") && params.get("room")) {
    history.replaceState(null, "", location.pathname + (sdk().isDesktop ? "?client=desktop" : ""));
    joinFromInvite(params.get("join"), params.get("room"));
  }
})();
requestAnimationFrame(frame);
})();
