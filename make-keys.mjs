// Run once, from this folder:  node make-keys.mjs
// Makes the map's signing key, its successor, and one operator agent key, and keeps them OUTSIDE
// this project folder (in ~/tithonus-keys/net), so archiving or uploading the folder never moves them.
// Then stores what the Worker needs as Cloudflare secrets. Safe to run again: existing keys are reused.
import { generateKeyPairSync, createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const dir = path.join(os.homedir(), "tithonus-keys", "net");
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

function keyFile(name) {
  const p = path.join(dir, name);
  if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  const jwk = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
  fs.writeFileSync(p, JSON.stringify(jwk), { mode: 0o600 });
  return jwk;
}

const signing = keyFile("signing-key.jwk");
const successor = keyFile("successor-key-KEEP-OFFLINE.jwk");
const operator = keyFile("operator-agent-key.jwk");
// The token that opens the operator's private records (/use, /paths). pull-data.mjs reads it from here.
const tokenPath = path.join(dir, "stats-token.txt");
if (!fs.existsSync(tokenPath)) fs.writeFileSync(tokenPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
const statsToken = fs.readFileSync(tokenPath, "utf8").trim();
const successorHash = createHash("sha256").update(Buffer.from(successor.x, "base64url")).digest("hex");

function put(name, value) {
  console.log(`\nSetting ${name} on Cloudflare...`);
  const r = spawnSync("npx", ["wrangler", "secret", "put", name], { input: value, stdio: ["pipe", "inherit", "inherit"] });
  if (r.status !== 0) {
    console.error(`\nCould not set ${name}. Check you're in the tithonus-net folder and logged into the tithonus.net account (npx wrangler whoami).`);
    process.exit(1);
  }
}

put("SIGNING_KEY", JSON.stringify(signing));
put("SUCCESSOR", successorHash);
put("OPERATORS", operator.x);
put("STATS_TOKEN", statsToken);

console.log(`
Done.
Keys are in ${dir}
  signing-key.jwk                  the map's current signing key (also stored on Cloudflare)
  successor-key-KEEP-OFFLINE.jwk   copy this to a USB stick or paper, then delete it from the Mac
  operator-agent-key.jwk           your first operator agent's key (used by seed.mjs)
  stats-token.txt                  opens your private records (used by pull-data.mjs and the test)
Map public key:  ${signing.x}
Successor hash:  ${successorHash}
Operator key:    ${operator.x}
`);
