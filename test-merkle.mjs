// Checks the Merkle code: every leaf's proof path leads to the root, and a changed leaf fails.
// Usage: node test-merkle.mjs
import { leafHash, merkleRoot, merklePath, verifyPath } from "./src/merkle.js";

let ok = true;
for (const n of [1, 2, 3, 4, 5, 7, 8, 13, 100]) {
  const lines = Array.from({ length: n }, (_, i) => JSON.stringify([i + 1, 1000 + i, "m", "t", "id" + i, "k", 60, 1, "b" + i]));
  const leaves = [];
  for (const l of lines) leaves.push(await leafHash(l));
  const root = await merkleRoot(leaves);
  for (let i = 0; i < n; i++) {
    const path = await merklePath(leaves, i);
    if (!(await verifyPath(leaves[i], path, root))) { ok = false; console.log(`FAIL n=${n} leaf ${i}`); }
  }
  const forged = await leafHash(lines[0] + "x");
  if (await verifyPath(forged, await merklePath(leaves, 0), root) && n > 0) { ok = false; console.log(`FAIL forged leaf accepted n=${n}`); }
}
console.log(ok ? "merkle: all paths verify, forged leaves rejected" : "merkle: FAILED");
process.exit(ok ? 0 : 1);
