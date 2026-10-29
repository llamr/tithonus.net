// Copies everything tithonus.net has observed to this Mac, so nothing is lost when the map prunes after 7 days.
// Run it any time, at least once a week (daily is best):   node pull-data.mjs
// Saves into ~/tithonus-data/net (outside the project folder, so archiving the folder never moves it).
// Files already saved for finished hours and days are skipped, so running it often is cheap.
// Its requests show up in /use and /paths with the client name "tithonus-pull", so you can filter them out.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const BASE = (process.argv[2] || "https://tithonus.net").replace(/\/$/, "");
const DIR = process.argv[3] || path.join(os.homedir(), "tithonus-data", "net");
for (const d of ["use", "paths", "feed", "snapshots"]) fs.mkdirSync(path.join(DIR, d), { recursive: true });

const TOKEN_FILE = path.join(os.homedir(), "tithonus-keys", "net", "stats-token.txt");
const TOKEN = process.env.TN_STATS_TOKEN || (fs.existsSync(TOKEN_FILE) ? fs.readFileSync(TOKEN_FILE, "utf8").trim() : "");
if (!TOKEN) console.log(`No stats token found at ${TOKEN_FILE}; run node make-keys.mjs first. Private records will be skipped.`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const save = (p, obj) => fs.writeFileSync(path.join(DIR, p), JSON.stringify(obj));
const have = (p) => fs.existsSync(path.join(DIR, p));
const dayName = (d) => new Date(d * 86400000).toISOString().slice(0, 10);
const hourName = (h) => new Date(h * 3600000).toISOString().slice(0, 13).replace("T", "-");
const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");

async function get(p) {
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(BASE + p, { headers: { "user-agent": "tithonus-pull/1", "tn-stats": TOKEN } });
      if (r.ok) return await r.json();
      if (r.status === 429) await sleep(11000);
    } catch (_) {}
    await sleep(2000);
  }
  return null;
}

const now = Date.now();
const today = Math.floor(now / 86400000);
const hourNow = Math.floor(now / 3600000);
let saved = 0, skipped = 0, failed = 0;

// 1. Usage counts for the last week (overlapping copies are fine; the newest is the fullest).
const use = await get("/use?hours=168");
if (use) { save(`use/${stamp}.json`, use); saved++; } else failed++;

// 1b. Reports sent to the operator (all of them, each pull; they are small).
const reps = await get("/reports?after=0");
if (reps) { save(`snapshots/${stamp}-reports.json`, reps); saved++; } else failed++;

// 2. Snapshots of what is live right now.
for (const [name, p] of [["swarms", "/swarms"], ["physics", "/physics"], ["stats", "/stats"]]) {
  const x = await get(p);
  if (x) { save(`snapshots/${stamp}-${name}.json`, x); saved++; } else failed++;
}

// 3. Paths, one file per day. Finished days are kept once saved; today and yesterday are refreshed.
for (let d = today - 7; d <= today; d++) {
  const file = `paths/${dayName(d)}.json`;
  if (d < today - 1 && have(file)) { skipped++; continue; }
  const rows = [];
  let from = 0, head = null, ok = true;
  while (from !== null) {
    const x = await get(`/paths?day=${d}&from=${from}`);
    if (!x) { ok = false; break; }
    head = head || x;
    rows.push(...x.r);
    from = x.next;
  }
  if (!ok) { failed++; continue; }
  if (rows.length || d >= today - 1) { save(file, { day: d, date: dayName(d), grammar: head.grammar, cols: head.cols, r: rows }); saved++; }
}

// 4. The public feed, one file per hour, with its Merkle root. Closed hours are kept once saved.
for (let h = hourNow - 7 * 24; h <= hourNow; h++) {
  const file = `feed/${hourName(h)}.json`;
  if (have(file)) { skipped++; continue; }
  const ev = [];
  let after = 0, head = null, ok = true;
  for (;;) {
    const x = await get(`/e/${h}?after=${after}`);
    if (!x) { ok = false; break; }
    head = head || x;
    ev.push(...x.ev);
    if (x.next === null) break;
    after = x.next;
  }
  if (!ok) { failed++; continue; }
  // An hour is final once anchored; an hour with no activity is final once it is well past.
  if ((head.closed && head.root) || (!head.root && !ev.length && h < hourNow - 2)) { save(file, { hour: h, when: hourName(h), root: head.root, receipt: head.receipt, cols: head.cols, kinds: head.kinds, ev }); saved++; }
  await sleep(100);
}

console.log(`Saved ${saved} files, skipped ${skipped} already saved, ${failed} failed.\nData is in ${DIR}`);
