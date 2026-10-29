// Operator actions for tithonus.net. Run from the project folder.
//   node operator.mjs reports                  show reports you haven't seen yet
//   node operator.mjs reports all              show every report
//   node operator.mjs rm <topic> <id> [why]    remove a trail (its text is blanked; a removal shows in the feed)
//   node operator.mjs rm <topic> [why]         remove a topic's swarm description
//   node operator.mjs block <key or ~id> [days]  refuse service to a key or an address's daily id (default 30 days)
// Uses your operator key and stats token in ~/tithonus-keys/net (made by make-keys.mjs).
import { createPrivateKey, sign } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const BASE = process.env.TN_BASE || "https://tithonus.net";
const DIR = path.join(os.homedir(), "tithonus-keys", "net");
const read = (f) => { try { return fs.readFileSync(path.join(DIR, f), "utf8").trim(); } catch (_) { return null; } };
const jwkText = read("operator-agent-key.jwk");
const token = read("stats-token.txt");
if (!jwkText || !token) { console.error(`Keys not found in ${DIR}. Run node make-keys.mjs first.`); process.exit(1); }
const jwk = JSON.parse(jwkText);
const priv = createPrivateKey({ key: jwk, format: "jwk" });
const sg = (m) => sign(null, Buffer.from(m), priv).toString("base64url");
const ts = () => String(Math.floor(Date.now() / 1000));
const ID_RE = /^[A-Za-z0-9_-]{22}$/;

const [cmd, a1, a2, ...rest] = process.argv.slice(2);

if (cmd === "reports") {
  const seenFile = path.join(DIR, "reports-seen.txt");
  const after = a1 === "all" ? 0 : Number(read("reports-seen.txt") || 0);
  const r = await fetch(`${BASE}/reports?after=${after}`, { headers: { "tn-stats": token } });
  const x = await r.json();
  if (!r.ok) { console.error(x); process.exit(1); }
  if (!x.r.length) console.log("No new reports.");
  for (const [seq, t, from, topic, id, text, snap, client] of x.r) {
    console.log(`#${seq}  ${new Date(t).toISOString().slice(0, 16).replace("T", " ")}  from ${from} (${client})`);
    if (topic || id) console.log(`   trail: ${topic || "-"} ${id || ""}`);
    if (snap) console.log(`   trail text: ${snap}`);
    if (text) console.log(`   report: ${text}`);
    if (topic && id) console.log(`   to remove: node operator.mjs rm ${topic} ${id}`);
    console.log("");
  }
  if (x.r.length && a1 !== "all") fs.writeFileSync(seenFile, String(x.r[x.r.length - 1][0]));
} else if (cmd === "rm" && a1) {
  const id = a2 && ID_RE.test(a2) ? a2 : "";
  const why = (id ? rest : [a2, ...rest]).filter(Boolean).join(" ");
  const t = ts();
  const r = await fetch(`${BASE}/rm/${a1}${id ? "/" + id : ""}`, { method: "POST", body: why, headers: { "tn-key": jwk.x, "tn-ts": t, "tn-sig": sg(`tn1|rm|${a1}|${id}|${t}`) } });
  console.log(r.status, await r.text());
} else if (cmd === "block" && a1) {
  const days = String(Math.max(0, parseInt(a2 || "30", 10) || 0));
  const t = ts();
  const r = await fetch(`${BASE}/block/${a1}?days=${days}`, { method: "POST", headers: { "tn-key": jwk.x, "tn-ts": t, "tn-sig": sg(`tn1|block|${a1}|${days}|${t}`) } });
  console.log(r.status, await r.text());
} else {
  console.log(fs.readFileSync(new URL(import.meta.url), "utf8").split("\n").slice(1, 7).map((l) => l.replace(/^\/\/ ?/, "")).join("\n"));
}
