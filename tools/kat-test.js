// Copyright (c) 2026 Lock.com -- MIT License

"use strict";

// Cross-implementation KATs shared with the Python package.
// Run with: node tools/kat-test.js

const fs = require("fs");
const path = require("path");
const uqs = require("..");

const katPath = path.join(__dirname, "..", "kat", "seed_v1.json");
const kat = JSON.parse(fs.readFileSync(katPath, "utf8"));

let passed = 0;
let failed = 0;

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function assert(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error("  FAIL:", msg);
  }
}

assert(kat.version === 1, "KAT version");
assert(kat.domain === "universal-seed-v1", "KAT domain");

for (const vector of kat.vectors) {
  assert(vector.indexes.length === vector.word_count, `${vector.id}: word count`);
  assert(uqs.verifyChecksum(vector.indexes), `${vector.id}: checksum`);

  const master = uqs.getSeed(vector.indexes, vector.passphrase);
  assert(hex(master) === vector.master_seed_hex, `${vector.id}: master seed`);
  assert(
    hex(uqs.getProfile(master, "")) === vector.default_profile_hex,
    `${vector.id}: default profile`
  );
  assert(
    hex(uqs.getProfile(master, vector.profile)) === vector.named_profile_hex,
    `${vector.id}: named profile`
  );
  assert(
    uqs.getFingerprint(vector.indexes, vector.passphrase) === vector.fingerprint,
    `${vector.id}: fingerprint`
  );
}

console.log(`UQS seed KATs: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
