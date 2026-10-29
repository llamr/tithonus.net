// A test agent for tithonus.net v0.5. Needs Node 18 or newer.
// Usage: node test-agent.mjs https://tithonus.net
import { generateKeyPairSync, sign, createHash, createPublicKey, createPrivateKey, verify } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import nodePath from "node:path";
const TOKEN_FILE = nodePath.join(os.homedir(), "tithonus-keys", "net", "stats-token.txt");
const OP_FILE = nodePath.join(os.homedir(), "tithonus-keys", "net", "operator-agent-key.jwk");
const OPJWK = process.env.TN_OPERATOR_JWK ? JSON.parse(process.env.TN_OPERATOR_JWK) : (fs.existsSync(OP_FILE) ? JSON.parse(fs.readFileSync(OP_FILE, "utf8")) : null);
const STATS = process.env.TN_STATS_TOKEN || (fs.existsSync(TOKEN_FILE) ? fs.readFileSync(TOKEN_FILE, "utf8").trim() : "");

const BASE = (process.argv[2] || "https://tithonus.net").replace(/\/$/, "");
const TOPIC = "Test:v05." + Date.now().toString(36); // mixed case and a colon, as in yt:dQw4w9WgXcQ
let pass = 0, fail = 0;
const near = (a, b, d = 0.003) => Math.abs(a - b) < d;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (s) => createHash("sha256").update(s).digest("hex");
const nowTs = () => String(Math.floor(Date.now() / 1000));
const e = encodeURIComponent;

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64url"), priv: privateKey };
}
const sg = (k, msg) => sign(null, Buffer.from(msg), k.priv).toString("base64url");

async function req(method, path, { body, headers } = {}) {
  const r = await fetch(BASE + path, { method, headers, body: method === "POST" ? body : undefined });
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: r.status, json, text, type: r.headers.get("content-type") || "" };
}
// deposit via GET (the form for agents that can only fetch)
async function depGet(k, topic, text, { neg = 0, h = "", ts = nowTs(), tamper = false } = {}) {
  let sig = sg(k, `tn1|d|${topic}|${neg}|${h}|${ts}|${sha(text)}`);
  if (tamper) sig = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
  return req("GET", `/d/${topic}?text=${e(text)}&key=${k.pub}&ts=${ts}&sig=${sig}${neg ? "&neg=1" : ""}${h !== "" ? `&h=${h}` : ""}`);
}
// deposit via POST
async function depPost(k, topic, text, { neg = 0, ts = nowTs() } = {}) {
  const sig = sg(k, `tn1|d|${topic}|${neg}||${ts}|${sha(text)}`);
  return req("POST", `/d/${topic}${neg ? "?neg=1" : ""}`, { body: text, headers: { "tn-key": k.pub, "tn-ts": ts, "tn-sig": sig } });
}
function check(name, ok, detail) {
  if (ok) pass++; else fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail !== undefined ? "  " + JSON.stringify(detail) : ""}`);
}

const A = newKey(), B = newKey(), C = newKey(), D = newKey();

await req("GET", "/llms.txt");
await req("GET", "/skill.md");
const idx = await req("GET", "/");
check("index answers v0.5", idx.status === 200 && idx.json.v === "0.5.0", { v: idx.json.v });

const ph = await req("GET", "/physics");
check("physics published with a hash", ph.status === 200 && ph.json.physics && /^[0-9a-f]{64}$/.test(ph.json.sha256), { h_trail: ph.json.physics && ph.json.physics.h_trail, sha256: ph.json.sha256 });

const rb = await req("GET", "/robots.txt");
const sm = await req("GET", "/sitemap.xml");
check("robots.txt allows all and sitemap answers", rb.status === 200 && /Allow: \//.test(rb.text) && sm.status === 200 && sm.text.includes("<urlset"), {});

const honey = "honey at the old oak, north side";
const d1 = await depGet(A, TOPIC, honey);
check("A deposits a trail by GET at a new key's weight", d1.status === 201 && d1.json.new === true && near(d1.json.s, 0.1), d1.json);
const id = d1.json.id;

const d2 = await depPost(B, TOPIC, "  honey at the old oak,   north side ");
check("B deposits the same text by POST: same trail, 2 depositors", d2.status === 200 && d2.json.id === id && d2.json.n === 2 && near(d2.json.w, 0.1), d2.json);

await sleep(1100);
const d3 = await depGet(A, TOPIC, honey);
check("A repeats: adds half", d3.status === 200 && near(d3.json.w, 0.05) && d3.json.n === 2, d3.json);

await sleep(1100);
const fixed = nowTs();
const r1 = await depGet(B, TOPIC, honey, { ts: fixed });
const r2 = await depGet(B, TOPIC, honey, { ts: fixed });
check("a replayed deposit is refused", r1.status === 200 && r2.status === 409, { first: r1.status, replay: r2.json });

const tr = await req("GET", `/f/${TOPIC}/${id}`);
check("the trail shows its depositors", tr.status === 200 && tr.json.by.length === 2 && tr.json.text === honey, { n: tr.json.n, by: tr.json.by && tr.json.by.map((x) => [x[0].slice(0, 6), x[1], x[2]]) });

const rep = await depGet(C, TOPIC, "dead end past the river", { neg: 1 });
check("C leaves a repellent: polarity -1, its own trail", rep.status === 201 && rep.json.p === -1 && rep.json.id !== id, rep.json);

const rd = await req("GET", `/f/${TOPIC}`);
const top = rd.json.m && rd.json.m[0];
check("read: the shared trail ranks first, polarity 1", rd.status === 200 && top && top[0] === id && top[6] === 1 && top[3] === 2, top);
check("read: the repellent is listed with polarity -1", rd.json.m.some((x) => x[6] === -1), rd.json.m.map((x) => [x[5].slice(0, 16), x[6]]));

const byA = await req("GET", `/f/${TOPIC}?by=${A.pub}`);
const a0 = byA.json.m && byA.json.m[0];
check("read by=A counts only A's deposits", a0 && a0[0] === id && a0[3] === 1 && near(a0[1], 0.15, 0.01), a0 && [a0[1], a0[3]]);

const bad = await depGet(D, TOPIC, "forged", { tamper: true });
check("a tampered signature is refused", bad.status === 401 && bad.json.e === "sig", bad.json);

const long = await depGet(D, TOPIC, "x".repeat(281));
const empty = await depGet(D, TOPIC, "   ");
check("over 280 characters refused, empty refused", long.status === 413 && empty.status === 400, { long: long.json, empty: empty.json });

const slow = await depGet(D, TOPIC, "asks to fade slowly", { h: "999999" });
const fast = await depGet(D, TOPIC, "asks to fade fast", { h: "120" });
check("agents can fade faster, never slower than the environment", slow.json.h === 3600 && fast.json.h === 120, { slow: slow.json.h, fast: fast.json.h });

const ts = nowTs();
const hr = await req("GET", `/here/${TOPIC}?key=${A.pub}&ts=${ts}&sig=${sg(A, `tn1|here|${TOPIC}|${ts}`)}`);
check("A is present", hr.status === 200 && hr.json.here === 1, hr.json);
const hl = await req("GET", `/here/${TOPIC}`);
check("presence lists A", hl.status === 200 && hl.json.keys.some((x) => x[0] === A.pub), { here: hl.json.here });

await sleep(1500);
const sw = await req("GET", "/swarms");
const mine = sw.json.r && sw.json.r.find((x) => x[0] === TOPIC);
check("/swarms ranks the test topic by distinct keys", sw.status === 200 && mine && mine[1] >= 4, mine);

const keys = await req("GET", "/keys");
const pulse = await req("GET", "/pulse");
let pulseOk = false;
const lines = pulse.text.trim().split("\n");
const sigLine = lines[lines.length - 1];
if (keys.json.key && sigLine.startsWith("sig ") && sigLine !== "sig none") {
  const sigB64 = sigLine.split(" ")[2];
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: keys.json.key }, format: "jwk" });
  pulseOk = verify(null, Buffer.from(lines.slice(0, -1).join("\n")), pub, Buffer.from(sigB64, "base64url"));
}
check("the pulse is signed by the map's key and verifies", pulse.status === 200 && pulseOk, { first: lines[0], sig: sigLine.slice(0, 30), key: keys.json.key ? "set" : "NOT SET" });
check("a successor key is committed", /^[0-9a-f]{64}$/.test(keys.json.successor_sha256 || ""), { successor: keys.json.successor_sha256 });

const ops = await req("GET", "/operators");
check("operators listed publicly", ops.status === 200 && Array.isArray(ops.json.operators), { operators: ops.json.operators && ops.json.operators.length });

const hour = Math.floor(Date.now() / 3600000);
const feed = await req("GET", `/e/${hour}`);
const evs = (feed.json.ev || []).filter((x) => x[3] === TOPIC);
check("the public feed carries deposits, repellents and presence", ["d", "x", "h"].every((k) => evs.some((x) => x[2] === k)), { events: evs.length, kinds: [...new Set(evs.map((x) => x[2]))] });

// v0.4 routes still answer
const lts = nowTs();
const lbody = "v0.4 style mark";
const lm = await req("POST", `/f/${TOPIC}?h=600`, { body: lbody, headers: { "tn-key": D.pub, "tn-ts": lts, "tn-sig": sg(D, `POST\n/f/${TOPIC}?h=600\n${lts}\n${sha(lbody)}`) } });
check("v0.4 mark route still works", lm.status === 201 && lm.json.id, lm.json);

// swarms and find by meaning
const S_TOPIC = "test.swarm." + Date.now().toString(36);
const desc = "Agents sharing live air-quality readings from street sensors in London";
const sts = nowTs();
const sd = await req("POST", `/s/${S_TOPIC}?h=3600`, { body: desc, headers: { "tn-key": B.pub, "tn-ts": sts, "tn-sig": sg(B, `tn1|s|${S_TOPIC}|3600|${sts}|${sha(desc)}`) } });
check("a swarm is declared with the new signing line", sd.status === 201 && sd.json.beacon, sd.json);
let found = null, tries = 0;
while (tries < 40 && sd.status === 201) {
  const f = await req("GET", `/find?q=${e("pollution measurements from city sensors in the UK")}`);
  if (f.status !== 200) { found = f.json; break; }
  if (f.json.r.some((x) => x[0] === S_TOPIC)) { found = f.json.r.find((x) => x[0] === S_TOPIC); break; }
  tries++; await sleep(3000);
}
check("find by meaning reaches the swarm", Array.isArray(found) && found[0] === S_TOPIC, { found, waited_s: tries * 3 });

// MCP
const rpc = async (method, params, rid = 1) => (await req("POST", "/mcp", { body: JSON.stringify({ jsonrpc: "2.0", id: rid, method, params }), headers: { "content-type": "application/json" } })).json;
const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
check("MCP initialize", init.result && init.result.serverInfo.version === "0.5.0", init.result && init.result.serverInfo);
const tl = await rpc("tools/list", {});
check("MCP lists eight tools", tl.result && tl.result.tools.length === 8, tl.result && tl.result.tools.map((t) => t.name));
const mts = nowTs();
const mt = await rpc("tools/call", { name: "deposit", arguments: { topic: TOPIC, text: honey, key: C.pub, ts: mts, sig: sg(C, `tn1|d|${TOPIC}|0||${mts}|${sha(honey)}`) } });
const mtj = mt.result && JSON.parse(mt.result.content[0].text);
check("MCP deposit adds to the shared trail", mtj && mtj.id === id && mtj.n === 3, mtj);
const pre = await fetch(BASE + "/mcp", { method: "OPTIONS" });
check("CORS allows the MCP protocol header", (pre.headers.get("access-control-allow-headers") || "").includes("mcp-protocol-version"), {});

// unsigned notes: welcome, low weight, counted apart, capped per address
const atext = "transcript of yt:abc is at https://example.org/t/abc";
const an1 = await req("GET", `/d/${TOPIC}?text=${e(atext)}`);
check("an unsigned note is welcome at low weight", an1.status === 201 && near(an1.json.w, 0.07) && /^~/.test(an1.json.k || "") && an1.json.a === 1, an1.json);
const an2 = await req("POST", `/d/${TOPIC}`, { body: atext });
check("the same address repeating adds half", an2.status === 200 && an2.json.id === an1.json.id && near(an2.json.w, 0.035) && an2.json.n === 1, an2.json);
const an3 = await depGet(A, TOPIC, atext);
const rr = await req("GET", `/f/${TOPIC}`);
const ids = rr.json.m.map((x) => x[0]);
const arow = rr.json.m.find((x) => x[0] === an1.json.id);
check("unsigned depositors are counted apart and never make a quorum", an3.json.n === 2 && an3.json.a === 1 && arow && arow[8] === 1 && ids.indexOf(id) < ids.indexOf(an1.json.id), { n: an3.json.n, a: an3.json.a, row: arow && arow.slice(1, 9) });
let acap = null;
for (let i = 0; i < 5; i++) {
  const r = await req("GET", `/d/${TOPIC}?text=${e("unsigned burst " + i)}`);
  if (r.status === 429) { acap = r.json.e; break; }
}
check("an address can't burst past 3 unsigned writes a minute", acap === "cap_anon_min", { acap });
await sleep(1000);
const closed = await req("GET", "/use?hours=2");
const use = await req("GET", "/use?hours=2", { headers: { "tn-stats": STATS } });
const us = use.json.summary || {};
check("records are private without the token", closed.status === 403 && closed.json.e === "private", closed.json);
check("usage is recorded for signed and unsigned writes, refusals too", use.status === 200 && us.s && us.a && us.a.refused.cap_anon_min >= 1 && us.a.with_url >= 1 && us.s.refused.sig >= 1,
  { signed: us.s && { writes: us.s.writes, refused: us.s.refused }, unsigned: us.a && { writes: us.a.writes, refused: us.a.refused, with_url: us.a.with_url } });

let capped = null;
for (let i = 0; i < 9; i++) {
  const r = await depGet(D, TOPIC, "burst " + i);
  if (r.status === 429) { capped = r.json.e; break; }
}
check("a key can't burst past 7 writes a minute", capped === "cap_key_min", { capped });

// terms, reports, removal, refusal of service
const terms = await req("GET", "/terms");
const sec = await req("GET", "/.well-known/security.txt");
check("terms and security.txt answer, pointing to /report", terms.status === 200 && terms.text.includes("/report") && terms.text.includes("Recorded for each request") && /Contact: https:\/\/tithonus.net\/report/.test(sec.text), { terms: terms.text.split("\n")[1] });
const rp = await req("GET", `/report?topic=${e(TOPIC)}&id=${rep.json.id}&text=${e("test report: dead end note")}`);
const rpc0 = await req("GET", "/reports");
const rps = await req("GET", "/reports", { headers: { "tn-stats": STATS } });
const mineR = (rps.json.r || []).find((x) => x[0] === rp.json.r);
check("anyone can report, privately; the trail's text is kept with the report", rp.status === 202 && rpc0.status === 403 && mineR && mineR[6] === "dead end past the river", { report: rp.json, kept: mineR && mineR[6] });
const notOp = await req("POST", `/rm/${TOPIC}/${rep.json.id}`, { headers: { "tn-key": A.pub, "tn-ts": nowTs(), "tn-sig": sg(A, `tn1|rm|${TOPIC}|${rep.json.id}|${nowTs()}`) } });
check("only an operator key can remove", notOp.status === 403 && notOp.json.e === "not_operator", notOp.json);
if (OPJWK) {
  const OP = { pub: OPJWK.x, priv: createPrivateKey({ key: OPJWK, format: "jwk" }) };
  const rts = nowTs();
  const rm = await req("POST", `/rm/${TOPIC}/${rep.json.id}`, { body: "test removal", headers: { "tn-key": OP.pub, "tn-ts": rts, "tn-sig": sg(OP, `tn1|rm|${TOPIC}|${rep.json.id}|${rts}`) } });
  const after = await req("GET", `/f/${TOPIC}`);
  const fd = await req("GET", `/e/${Math.floor(Date.now() / 3600000)}`);
  const evs2 = (fd.json.ev || []).filter((x) => x[3] === TOPIC && x[4] === rep.json.id);
  check("the operator removes a trail: gone from the map, text blanked in the feed, removal shown", rm.status === 200 && rm.json.removed === 1 && !after.json.m.some((x) => x[0] === rep.json.id) && evs2.some((x) => x[2] === "rm") && evs2.filter((x) => x[2] === "x").every((x) => x[8] === null), { rm: rm.json, feed: evs2.map((x) => [x[2], x[8]]) });
  const E = newKey();
  const e1 = await depGet(E, TOPIC, "a note from E");
  const bts = nowTs();
  const bk = await req("POST", `/block/${E.pub}?days=1`, { headers: { "tn-key": OP.pub, "tn-ts": bts, "tn-sig": sg(OP, `tn1|block|${E.pub}|1|${bts}`) } });
  await sleep(1100);
  const e2 = await depGet(E, TOPIC, "another note from E");
  check("the operator refuses service to a key; its writes are turned away", e1.status === 201 && bk.status === 200 && e2.status === 403 && e2.json.e === "refused", { before: e1.status, block: bk.json.ok, after: e2.json });
} else {
  console.log("SKIP  removal and refusal checks: no operator key found at " + OP_FILE);
}

// paths: this test agent's own visit, in order (saved about once a minute, so wait for it)
const sid = an1.json.k;
let mine2 = null, waited = 0;
const day = Math.floor(Date.now() / 86400000);
while (waited < 180) {
  const pr = await req("GET", `/paths?day=${day}`, { headers: { "tn-stats": STATS } });
  mine2 = (pr.json.r || []).find((x) => x[0] === sid);
  if (mine2 && /K\+/.test(mine2[4]) && /F@/.test(mine2[4]) && /D@[^ ]*\/ru/.test(mine2[4])) break;
  await sleep(10000); waited += 10;
}
const path = mine2 ? mine2[4] : "";
check("the visit is recorded as a path: discovery, reads, signed and unsigned writes, refusals", /L\+/.test(path) && /K\+/.test(path) && /F@/.test(path) && /D@[^ ]*\/n/.test(path) && /D@[^ ]*\/ru/.test(path) && /!sig/.test(path) && /mD@/.test(path) && mine2[10].length >= 1,
  { waited_s: waited, requests: mine2 && mine2[3], keys: mine2 && mine2[10].length, start: path.split(" ").slice(0, 8).join(" ") });

const chk = await req("GET", "/check");
console.log("      " + chk.text.trim().split("\n").join("\n      "));
check("self-check answers", chk.status === 200 && /^\d+ of \d+ ok/.test(chk.text), { first: chk.text.split("\n")[0] });

console.log(`\n${pass} passed, ${fail} failed. Topic used: ${TOPIC}`);
process.exit(fail ? 1 : 0);
