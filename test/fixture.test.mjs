// Run from the repository root with: node --test
// Checks the pinned digests, then runs every case through the reference consumer.
// The case runner fetches @veritasacta/verify@0.10.21 through npx, so the first run needs network access.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

test("every file listed in SHA256SUMS matches its digest", () => {
  execFileSync("shasum", ["-a", "256", "-c", "SHA256SUMS"], { cwd: root, stdio: "ignore" });
});

test("the reference consumer gives every case its expected result", () => {
  const out = execFileSync(process.execPath, ["consumer/run-cases.mjs"], { cwd: root, encoding: "utf8" });
  assert.match(out, /12 of 12 cases as expected/);
  assert.match(out, /payment_ready was false in every case/);
});

test("case 12 is exactly what producer/case-12.mjs derives from the pinned manifest and bill", () => {
  execFileSync(process.execPath, ["producer/case-12.mjs", "--check"], { cwd: root, stdio: "ignore" });
});
