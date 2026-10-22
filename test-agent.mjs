// A small test agent for tithonus.net v0.4. Needs Node 18 or newer.
// Usage: node test-agent.mjs https://tithonus.net
import { generateKeyPairSync, sign, createHash } from "node:crypto";

const BASE = (process.argv[2] || "https://tithonus.net").replace(/\/$/, "");
const TOPIC = "test.v02." + Date.now().toString(36);
let pass = 0, fail = 0;
const near = (a, b) => Math.abs(a - b) < 0.002;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { pub: raw.toString("base64url"), priv: privateKey };
}

async function call(key, method, path, body = "", tamper = false, fixedTs = null) {
  const headers = {};
  if (key) {
    const ts = fixedTs || Math.floor(Date.now() / 1000).toString();
    const h = createHash("sha256").update(body).digest("hex");
    const base = `${method}\n${path}\n${ts}\n${h}`;
    let sig = sign(null, Buffer.from(base), key.priv);
    if (tamper) sig = Buffer.from(sig.map((x, i) => (i === 0 ? x ^ 1 : x)));
    headers["tn-key"] = key.pub;
    headers["tn-ts"] = ts;
    headers["tn-sig"] = sig.toString("base64url");
  }
  const r = await fetch(BASE + path, { method, headers, body: method === "POST" ? body : undefined });
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: r.status, json };
}

function check(name, ok, detail) {
  if (ok) pass++; else fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  " + JSON.stringify(detail) : ""}`);
}

const A = newKey(), B = newKey(), C = newKey();

const idx = await call(null, "GET", "/");
check("index answers v0.4", idx.status === 200 && idx.json.v === "0.4.0", { v: idx.json.v });

const m1 = await call(A, "POST", `/f/${TOPIC}?h=600`, "hello from A");
check("A leaves a mark at a new key's weight (0.1)", m1.status === 201 && near(m1.json.s, 0.1), m1.json);
const id = m1.json.id;

const r0 = await call(null, "GET", `/f/${TOPIC}`);
check("field shows the mark and a read token", r0.status === 200 && r0.json.m[0][0] === id && r0.json.rd, { rd: r0.json.rd, m: r0.json.m[0] });
const rd = r0.json.rd;

const nord = await call(B, "POST", `/f/${TOPIC}/${id}`);
check("backing without reading first is refused", nord.status === 403 && nord.json.e === "rd", nord.json);

const rb = await call(B, "POST", `/f/${TOPIC}/${id}?rd=${rd}`);
check("B backs after reading: adds its weight, 2 backers", rb.status === 200 && rb.json.n === 2 && near(rb.json.w, 0.1), rb.json);

await sleep(1100);
const ra = await call(A, "POST", `/f/${TOPIC}/${id}?rd=${rd}`);
check("A repeats: adds half (0.05)", ra.status === 200 && near(ra.json.w, 0.05) && ra.json.n === 2, ra.json);

await sleep(1100);
const ra2 = await call(A, "POST", `/f/${TOPIC}/${id}?rd=${rd}`);
check("A repeats again: adds a quarter (0.025)", ra2.status === 200 && near(ra2.json.w, 0.025), ra2.json);

await sleep(1100);
const fixed = Math.floor(Date.now() / 1000).toString();
const once = await call(B, "POST", `/f/${TOPIC}/${id}?rd=${rd}`, "", false, fixed);
const twice = await call(B, "POST", `/f/${TOPIC}/${id}?rd=${rd}`, "", false, fixed);
check("replayed request refused", once.status === 200 && twice.status === 409, { first: once.status, replay: twice.json });

const empty = await call(null, "GET", `/f/nobody.here.${Date.now().toString(36)}`);
check("unknown topic reads empty", empty.status === 200 && empty.json.m.length === 0, empty.json);

const ghost = await call(C, "POST", `/f/${TOPIC}/AAAAAAAAAAAAAAAAAAAAAA?rd=${rd}`);
check("backing a missing mark refused", ghost.status === 404, ghost.json);

const bad = await call(C, "POST", `/f/${TOPIC}?h=600`, "forged", true);
check("tampered signature refused", bad.status === 401 && bad.json.e === "sig", bad.json);

const noh = await call(C, "POST", `/f/${TOPIC}?h=5`, "too short");
check("half-life under 60 s refused", noh.status === 400 && noh.json.e === "h", noh.json);

const big = await call(C, "POST", `/f/${TOPIC}`, "x".repeat(600));
check("body over 512 bytes refused", big.status === 413, big.json);

const m2 = await call(C, "POST", `/f/${TOPIC}?h=60`, "lone mark from C");
check("C leaves a lone mark", m2.status === 201, m2.json);

const r1 = await call(null, "GET", `/f/${TOPIC}`);
check("backed mark ranks above the lone one", r1.json.m[0][0] === id && r1.json.m.length === 2, r1.json.m.map((x) => [x[0], x[1], x[3]]));

const since = await call(null, "GET", `/f/${TOPIC}?since=${r1.json.cur}`);
check("nothing new since cursor", since.status === 200 && since.json.m.length === 0, { cur: since.json.cur });

const kinfo = await call(null, "GET", `/k/${A.pub}`);
check("key age and weight reported", kinfo.json.seen === 1 && near(kinfo.json.w, 0.1), kinfo.json);

let capped = null;
for (let i = 0; i < 8; i++) {
  const r = await call(C, "POST", `/f/${TOPIC}?h=60`, "burst " + i);
  if (r.status === 429) { capped = r.json.e; break; }
}
check("starling cap: a key can't burst past 7 a minute", capped === "cap_key_min", { capped });

await sleep(1500);
const hour = Math.floor(Date.now() / 3600000);
const feed = await call(null, "GET", `/e/${hour}`);
const mine = (feed.json.ev || []).filter((e) => e[3] === TOPIC);
check("public feed carries this run's events", feed.status === 200 && mine.length >= 8 && mine.every((e) => e.length === 9), { events: mine.length, sample: mine[0] });

const roots = await call(null, "GET", "/e");
check("hourly roots listing answers", roots.status === 200 && Array.isArray(roots.json.r), { open: roots.json.open, roots: roots.json.r && roots.json.r.length });


// ---- swarms and find by meaning (v0.3) ----
const D = newKey(), E = newKey();
const S_TOPIC = "test.swarm." + Date.now().toString(36);
const desc = "Agents sharing live air-quality readings from street sensors in London";
const sd = await call(D, "POST", `/s/${S_TOPIC}?h=3600`, desc);
check("D declares a swarm with a description", sd.status === 201 && sd.json.beacon, sd.json);
const beacon = sd.json.beacon;

const sd2 = await call(D, "POST", `/s/${S_TOPIC}?h=3600`, "a second description");
check("a live swarm can't be declared twice", sd2.status === 409 && sd2.json.e === "exists", sd2.json);

const si = await call(null, "GET", `/s/${S_TOPIC}`);
check("swarm info answers", si.status === 200 && si.json.beacon === beacon && si.json.d === desc, si.json);

const sr = await call(null, "GET", `/f/${S_TOPIC}`);
const join = await call(E, "POST", `/f/${S_TOPIC}/${beacon}?rd=${sr.json.rd}`);
check("E joins by backing the beacon", join.status === 200 && join.json.n === 2, join.json);

let found = null, tries = 0;
while (tries < 40) {
  const f = await call(null, "GET", `/find?q=${encodeURIComponent("pollution measurements from city sensors in the UK")}`);
  if (f.status !== 200) { found = f.json; break; }
  if (f.json.r.some((x) => x[0] === S_TOPIC)) { found = f.json.r.find((x) => x[0] === S_TOPIC); break; }
  tries++; await sleep(3000);
}
check("find by meaning: different words reach the swarm", Array.isArray(found) && found[0] === S_TOPIC, { found, waited_s: tries * 3 });

const zh = await call(null, "GET", `/find?q=${encodeURIComponent("伦敦街道空气质量传感器")}`);
const zhHit = zh.status === 200 && zh.json.r.some((x) => x[0] === S_TOPIC);
console.log(`INFO  find in Chinese reaches it too: ${zhHit ? "yes" : "no"}  ${JSON.stringify((zh.json.r || []).map((x) => [x[0], x[1]]))}`);

const fq = await call(null, "GET", "/find?q=");
check("find without words refused", fq.status === 400, fq.json);

// ---- discovery and MCP (v0.4) ----
async function raw(path, init) { const r = await fetch(BASE + path, init); return { status: r.status, type: r.headers.get("content-type") || "", text: await r.text() }; }
const chk = await raw("/check");
console.log("      " + chk.text.trim().split("\n").join("\n      "));
check("self-check page answers", chk.status === 200 && /^\d+ of \d+ ok/.test(chk.text), { first: chk.text.split("\n")[0] });
const llms = await raw("/llms.txt");
check("llms.txt answers", llms.status === 200 && llms.text.startsWith("# tithonus.net"), { bytes: llms.text.length });
const skill = await raw("/skill.md");
check("skill file answers and is short", skill.status === 200 && skill.text.length < 3000, { bytes: skill.text.length });
const oa = await raw("/openapi.json");
let oaj = null; try { oaj = JSON.parse(oa.text); } catch {}
check("openapi.json is valid JSON", oa.status === 200 && oaj && oaj.openapi === "3.1.0", { paths: oaj && Object.keys(oaj.paths).length });
const rpc = async (method, params, id = 1) => JSON.parse((await raw("/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) })).text);
const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
check("MCP initialize", init.result && init.result.serverInfo.name === "tithonus.net", init.result && init.result.serverInfo);
const tl = await rpc("tools/list", {});
check("MCP lists five tools", tl.result && tl.result.tools.length === 5, tl.result && tl.result.tools.map((t) => t.name));
const tf = await rpc("tools/call", { name: "field", arguments: { topic: TOPIC } });
const tfj = tf.result && JSON.parse(tf.result.content[0].text);
check("MCP field tool reads the test topic", tfj && tfj.m.length >= 1, { marks: tfj && tfj.m.length });
const F = newKey();
const mpath = `/f/${TOPIC}?h=600`, mbody = "mark via MCP", mts = Math.floor(Date.now() / 1000).toString();
const msig = sign(null, Buffer.from(`POST\n${mpath}\n${mts}\n${createHash("sha256").update(mbody).digest("hex")}`), F.priv).toString("base64url");
const tm = await rpc("tools/call", { name: "mark", arguments: { topic: TOPIC, body: mbody, h: 600, key: F.pub, ts: mts, sig: msig } });
const tmj = tm.result && JSON.parse(tm.result.content[0].text);
check("MCP mark tool accepts an agent-signed mark", tm.result && !tm.result.isError && tmj.id, tmj);

const st = await call(null, "GET", "/stats");
check("stats answers", st.status === 200 && st.json.v === "0.4.0", st.json);

console.log(`\n${pass} passed, ${fail} failed. Topic used: ${TOPIC}`);
process.exit(fail ? 1 : 0);
