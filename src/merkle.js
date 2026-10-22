// Merkle tree over hourly events.
// leaf = SHA-256(UTF-8 of the event's JSON line)
// node = SHA-256(left raw 32 bytes || right raw 32 bytes); an odd node is carried up unchanged.

const enc = new TextEncoder();

export function toHex(bytes) {
  return [...bytes].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function fromHex(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
async function sha(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function pair(a, b) {
  const buf = new Uint8Array(64);
  buf.set(fromHex(a), 0);
  buf.set(fromHex(b), 32);
  return toHex(await sha(buf));
}

export async function leafHash(line) {
  return toHex(await sha(enc.encode(line)));
}

export async function merkleRoot(leaves) {
  if (!leaves.length) return null;
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? await pair(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

// Path from leaf to root: list of [side, hash], side "L" = sibling on the left.
export async function merklePath(leaves, index) {
  const path = [];
  let level = leaves;
  let i = index;
  while (level.length > 1) {
    const sib = i % 2 === 0 ? i + 1 : i - 1;
    if (sib < level.length) path.push([i % 2 === 0 ? "R" : "L", level[sib]]);
    const next = [];
    for (let j = 0; j < level.length; j += 2) {
      next.push(j + 1 < level.length ? await pair(level[j], level[j + 1]) : level[j]);
    }
    level = next;
    i = Math.floor(i / 2);
  }
  return path;
}

export async function verifyPath(leaf, path, root) {
  let h = leaf;
  for (const [side, sib] of path) h = side === "L" ? await pair(sib, h) : await pair(h, sib);
  return h === root;
}
