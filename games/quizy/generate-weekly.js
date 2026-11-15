#!/usr/bin/env node
// Builds games/quizy/weekly.json: fresh multiple-choice questions from the Open Trivia DB (https://opentdb.com).
// Run weekly by .github/workflows/quizy-weekly.yml. Usage: node games/quizy/generate-weekly.js
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PER_SUBJECT = 20;
const CATEGORIES = {
  nature: [17, 27], music: [12], entertainment: [10, 13, 29, 32], culture: [20, 25], movies: [11, 14],
  places: [22], general: [9], science: [17, 30], history: [23], sport: [21], tech: [18], gaming: [15]
};
const sleep = ms => new Promise(r => setTimeout(r, ms));

function weekId(date) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - day);
  const yearStart = Date.UTC(d.getUTCFullYear(), 0, 1);
  return `${d.getUTCFullYear()}-W${String(Math.ceil(((d - yearStart) / 86400000 + 1) / 7)).padStart(2, '0')}`;
}

function loadBank() {
  const sandbox = { globalThis: {} };
  sandbox.globalThis.QuizyBank = { parts: [] };
  vm.createContext(sandbox);
  for (const f of ['questions-1.js', 'questions-2.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, f), 'utf8'), sandbox);
  return sandbox.globalThis.QuizyBank;
}

const dec = s => decodeURIComponent(s).trim();

async function fetchCategory(id) {
  const url = `https://opentdb.com/api.php?amount=50&category=${id}&type=multiple&encode=url3986`;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        const body = await res.json();
        if (body.response_code === 0) return body.results;
      }
    } catch (_) { /* retry */ }
    await sleep(6000);
  }
  return [];
}

async function main() {
  const bank = loadBank();
  const seen = new Set();
  for (const part of bank.parts) for (const list of Object.values(part.subjects || {})) for (const q of list) seen.add(String(q[0]).toLowerCase());

  const subjects = {};
  for (const [subject, ids] of Object.entries(CATEGORIES)) {
    const picked = [];
    for (const id of ids) {
      await sleep(5500); // OpenTDB allows one request per 5 seconds per IP
      for (const r of await fetchCategory(id)) {
        const q = [dec(r.question), dec(r.correct_answer), ...r.incorrect_answers.map(dec)];
        const key = q[0].toLowerCase();
        if (seen.has(key) || q.length !== 5 || q.some(s => !s || s.length > 120) || new Set(q.slice(1)).size !== 4) continue;
        seen.add(key);
        picked.push(q);
      }
    }
    picked.sort(() => Math.random() - 0.5);
    if (picked.length) subjects[subject] = picked.slice(0, PER_SUBJECT);
    console.log(`${subject}: ${(subjects[subject] || []).length} questions`);
  }

  if (!Object.keys(subjects).length) {
    console.error('No questions fetched; keeping the existing weekly.json.');
    return;
  }
  const out = { week: weekId(new Date()), generated: new Date().toISOString(), subjects };
  fs.writeFileSync(path.join(__dirname, 'weekly.json'), JSON.stringify(out, null, 1) + '\n');
}

main().catch(err => { console.error(err); process.exit(1); });
