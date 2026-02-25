// Copyright (c) 2026 Signer.io — MIT License

"use strict";

// Basic test harness — round-trip tests, edge cases, and cross-checks.
// Run with: node tools/test.js

const crypto = require("../crypto");
const { toBytes, randomBytes, constantTimeEqual } = require("../crypto/utils");

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error("  FAIL:", msg);
  }
}

function section(name) {
  console.log(`\n── ${name} ──`);
}

// ── Ed25519 ───────────────────────────────────────────────────────

section("Ed25519");

(() => {
  const seed = randomBytes(32);
  const { sk, pk } = crypto.ed25519Keygen(seed);
  assert(sk.length === 64, "sk should be 64 bytes");
  assert(pk.length === 32, "pk should be 32 bytes");

  // Round-trip sign/verify with Uint8Array
  const msg = new TextEncoder().encode("hello ed25519");
  const sig = crypto.ed25519Sign(msg, sk);
  assert(sig.length === 64, "sig should be 64 bytes");
  assert(crypto.ed25519Verify(msg, sig, pk), "valid sig should verify");

  // Verify with string message (toBytes normalization)
  const sig2 = crypto.ed25519Sign("hello ed25519", sk);
  assert(crypto.ed25519Verify("hello ed25519", sig2, pk), "string message should work");

  // Tampered message should fail
  assert(!crypto.ed25519Verify(new TextEncoder().encode("tampered"), sig, pk), "tampered msg should fail");

  // Tampered signature should fail
  const badSig = new Uint8Array(sig);
  badSig[0] ^= 0xff;
  assert(!crypto.ed25519Verify(msg, badSig, pk), "tampered sig should fail");

  // Wrong key should fail
  const { pk: pk2 } = crypto.ed25519Keygen(randomBytes(32));
  assert(!crypto.ed25519Verify(msg, sig, pk2), "wrong key should fail");

  // Cross-check with Node.js crypto if available
  try {
    const nodeCrypto = require("crypto");
    const skDer = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seed),
    ]);
    const privateKey = nodeCrypto.createPrivateKey({ key: skDer, format: "der", type: "pkcs8" });
    const nativeSig = nodeCrypto.sign(null, Buffer.from(msg), privateKey);
    // Our verify should accept native-generated signatures
    assert(crypto.ed25519Verify(msg, new Uint8Array(nativeSig), pk), "native sig should verify");
    console.log("  Ed25519 cross-check with Node.js crypto: OK");
  } catch (_) {
    console.log("  Ed25519 cross-check: skipped (native not available)");
  }

  console.log("  Ed25519 round-trip: OK");
})();

// ── X25519 ────────────────────────────────────────────────────────

section("X25519");

(() => {
  const seedA = randomBytes(32);
  const seedB = randomBytes(32);
  const alice = crypto.x25519Keygen(seedA);
  const bob = crypto.x25519Keygen(seedB);

  assert(alice.sk.length === 32, "sk should be 32 bytes");
  assert(alice.pk.length === 32, "pk should be 32 bytes");

  const ssA = crypto.x25519(alice.sk, bob.pk);
  const ssB = crypto.x25519(bob.sk, alice.pk);
  assert(constantTimeEqual(ssA, ssB), "shared secrets should match");

  // Cross-check with Node.js crypto if available
  try {
    const nodeCrypto = require("crypto");
    const skDer = Buffer.concat([
      Buffer.from("302e020100300506032b656e04220420", "hex"),
      Buffer.from(alice.sk),
    ]);
    const pkDer = Buffer.concat([
      Buffer.from("302a300506032b656e032100", "hex"),
      Buffer.from(bob.pk),
    ]);
    const privateKey = nodeCrypto.createPrivateKey({ key: skDer, format: "der", type: "pkcs8" });
    const publicKey = nodeCrypto.createPublicKey({ key: pkDer, format: "der", type: "spki" });
    const nativeSs = nodeCrypto.diffieHellman({ privateKey, publicKey });
    assert(constantTimeEqual(ssA, new Uint8Array(nativeSs)), "shared secret should match native");
    console.log("  X25519 cross-check with Node.js crypto: OK");
  } catch (_) {
    console.log("  X25519 cross-check: skipped (native not available)");
  }

  console.log("  X25519 key exchange: OK");
})();

// ── ML-DSA-65 ─────────────────────────────────────────────────────

section("ML-DSA-65");

(() => {
  const seed = randomBytes(32);
  const { sk, pk } = crypto.mlKeygen(seed);
  assert(sk.length === 4032, "sk should be 4032 bytes");
  assert(pk.length === 1952, "pk should be 1952 bytes");

  // Round-trip with Uint8Array message (raw/interoperable API)
  const msg = new TextEncoder().encode("hello ml-dsa");
  const sig = crypto.mlSign(msg, sk);
  assert(sig.length === 3309, "sig should be 3309 bytes");
  assert(crypto.mlVerify(msg, sig, pk), "valid sig should verify");

  // String message (toBytes normalization)
  const sig2 = crypto.mlSign("hello ml-dsa", sk);
  assert(crypto.mlVerify("hello ml-dsa", sig2, pk), "string message should work");

  // Context string (FIPS 204 pure mode via mlSignWithContext)
  const ctx = new TextEncoder().encode("test-ctx");
  const sigCtx = crypto.mlSignWithContext(msg, sk, ctx);
  assert(crypto.mlVerifyWithContext(msg, sigCtx, pk, ctx), "ctx sig should verify with same ctx");
  assert(!crypto.mlVerifyWithContext(msg, sigCtx, pk), "ctx sig should fail without ctx");

  // String context
  const sigCtx2 = crypto.mlSignWithContext(msg, sk, "test-ctx");
  assert(crypto.mlVerifyWithContext(msg, sigCtx2, pk, "test-ctx"), "string ctx should work");

  // Raw signature should NOT verify under context mode (and vice versa)
  assert(!crypto.mlVerifyWithContext(msg, sig, pk, ctx), "raw sig should fail under context verification");
  assert(!crypto.mlVerify(msg, sigCtx, pk), "context sig should fail under raw verification");

  // Deterministic mode
  const sigDet1 = crypto.mlSign(msg, sk, { deterministic: true });
  const sigDet2 = crypto.mlSign(msg, sk, { deterministic: true });
  assert(constantTimeEqual(sigDet1, sigDet2), "deterministic sigs should be identical");

  // Tampered
  assert(!crypto.mlVerify(new TextEncoder().encode("tampered"), sig, pk), "tampered msg should fail");

  console.log("  ML-DSA-65 round-trip: OK");
})();

// ── ML-DSA-65 Async ───────────────────────────────────────────────

section("ML-DSA-65 Async");

let asyncDone = false;

(async () => {
  try {
    const seed = randomBytes(32);
    const { sk, pk } = crypto.mlKeygen(seed);
    const msg = new TextEncoder().encode("hello ml-dsa-async");

    const sig = await crypto.mlSignAsync(msg, sk);
    assert(sig.length === 3309, "async sig should be 3309 bytes");

    const valid = await crypto.mlVerifyAsync(msg, sig, pk);
    assert(valid, "async verify should pass");

    const invalid = await crypto.mlVerifyAsync(new TextEncoder().encode("tampered"), sig, pk);
    assert(!invalid, "async verify should fail on tampered msg");

    console.log("  ML-DSA-65 Async: OK");
  } catch (e) {
    console.error("  FAIL: ML-DSA async exception:", e.message);
    failed++;
  }
  asyncDone = true;
})();

// ── ML-KEM-768 ────────────────────────────────────────────────────

section("ML-KEM-768");

(() => {
  const seed = randomBytes(64);
  const { ek, dk } = crypto.mlKemKeygen(seed);
  assert(ek.length === 1184, "ek should be 1184 bytes");
  assert(dk.length === 2400, "dk should be 2400 bytes");

  // Encaps/Decaps round-trip
  const { ct, ss: ssEnc } = crypto.mlKemEncaps(ek);
  assert(ct.length === 1088, "ct should be 1088 bytes");
  assert(ssEnc.length === 32, "ss should be 32 bytes");

  const ssDec = crypto.mlKemDecaps(dk, ct);
  assert(constantTimeEqual(ssEnc, ssDec), "encaps/decaps shared secrets should match");

  // Deterministic encaps
  const rnd = randomBytes(32);
  const r1 = crypto.mlKemEncaps(ek, rnd);
  const r2 = crypto.mlKemEncaps(ek, rnd);
  assert(constantTimeEqual(r1.ct, r2.ct), "deterministic encaps should produce same ct");
  assert(constantTimeEqual(r1.ss, r2.ss), "deterministic encaps should produce same ss");

  // Tampered ciphertext should produce different (implicit rejection) ss
  const badCt = new Uint8Array(ct);
  badCt[0] ^= 0xff;
  const ssBad = crypto.mlKemDecaps(dk, badCt);
  assert(!constantTimeEqual(ssEnc, ssBad), "tampered ct should produce different ss (implicit rejection)");

  console.log("  ML-KEM-768 round-trip: OK");
})();

// ── Hybrid DSA ────────────────────────────────────────────────────

section("Hybrid Ed25519 + ML-DSA-65");

(() => {
  const seed = randomBytes(64);
  const { sk, pk } = crypto.hybridDsaKeygen(seed);
  assert(sk.length === 4096, "sk should be 4096 bytes");
  assert(pk.length === 1984, "pk should be 1984 bytes");

  const msg = new TextEncoder().encode("hello hybrid");
  const sig = crypto.hybridDsaSign(msg, sk);
  assert(sig.length === 3373, "sig should be 3373 bytes");
  assert(crypto.hybridDsaVerify(msg, sig, pk), "valid sig should verify");

  // String message
  assert(crypto.hybridDsaVerify("hello hybrid", crypto.hybridDsaSign("hello hybrid", sk), pk),
    "string message should work");

  // Tampered
  assert(!crypto.hybridDsaVerify(new TextEncoder().encode("tampered"), sig, pk), "tampered should fail");

  // Verify stripping resistance: neither component should work standalone
  const edSig = sig.subarray(0, 64);
  const mlSig = sig.subarray(64);
  const edPk = pk.subarray(0, 32);
  const mlPk = pk.subarray(32);
  assert(!crypto.ed25519Verify(msg, edSig, edPk), "Ed25519 component should not verify standalone (domain-prefixed)");
  assert(!crypto.mlVerify(msg, mlSig, mlPk), "ML-DSA component should not verify standalone (domain-prefixed)");

  console.log("  Hybrid DSA round-trip: OK");
})();

// ── Hybrid KEM ────────────────────────────────────────────────────

section("Hybrid X25519 + ML-KEM-768");

(() => {
  const seed = randomBytes(96);
  const { ek, dk } = crypto.hybridKemKeygen(seed);
  assert(ek.length === 1216, "ek should be 1216 bytes");
  assert(dk.length === 2432, "dk should be 2432 bytes");

  const { ct, ss: ssEnc } = crypto.hybridKemEncaps(ek);
  assert(ct.length === 1120, "ct should be 1120 bytes");
  assert(ssEnc.length === 32, "ss should be 32 bytes");

  const ssDec = crypto.hybridKemDecaps(dk, ct);
  assert(constantTimeEqual(ssEnc, ssDec), "encaps/decaps shared secrets should match");

  // Tampered X25519 part of ciphertext — should not throw
  const badCt = new Uint8Array(ct);
  badCt[0] ^= 0xff; // tamper X25519 ephemeral pk
  try {
    const ssBad = crypto.hybridKemDecaps(dk, badCt);
    assert(!constantTimeEqual(ssEnc, ssBad), "tampered ct should produce different ss");
    console.log("  Hybrid KEM tampered X25519: OK (no throw)");
  } catch (e) {
    assert(false, "hybridKemDecaps should not throw on tampered X25519: " + e.message);
  }

  console.log("  Hybrid KEM round-trip: OK");
})();

// ── SHA-3 / SHAKE ─────────────────────────────────────────────────

section("SHA-3 / SHAKE");

(() => {
  // Empty input hash (known answer)
  const h = crypto.sha3_256(new Uint8Array(0));
  assert(h.length === 32, "sha3-256 should return 32 bytes");

  // String input (toBytes in sha3)
  const h2 = crypto.sha3_256("abc");
  assert(h2.length === 32, "sha3-256 of string should work");

  // ArrayBuffer input
  const abuf = new ArrayBuffer(3);
  new Uint8Array(abuf).set([0x61, 0x62, 0x63]); // "abc"
  const h3 = crypto.sha3_256(abuf);
  assert(constantTimeEqual(h2, h3), "sha3-256 of ArrayBuffer should match string");

  // SHAKE determinism
  const s1 = crypto.shake256(new Uint8Array([1, 2, 3]), 64);
  const s2 = crypto.shake256(new Uint8Array([1, 2, 3]), 64);
  assert(constantTimeEqual(s1, s2), "SHAKE should be deterministic");

  // SHAKE prefix consistency: shake256(data, 64) prefix should match shake256(data, 128)
  const long = crypto.shake256(new Uint8Array([1, 2, 3]), 128);
  assert(constantTimeEqual(s1, long.subarray(0, 64)), "SHAKE output should be prefix-consistent");

  console.log("  SHA-3/SHAKE: OK");
})();

// ── Argon2id ────────────────────────────────────────────────────

section("Argon2id");

(() => {
  // Basic round-trip: argon2id should return hashLen bytes
  const password = new TextEncoder().encode("password");
  const salt = new TextEncoder().encode("saltsalt"); // 8 bytes min
  const hash = crypto.argon2id(password, salt, 1, 64, 1, 32);
  assert(hash instanceof Uint8Array, "argon2id should return Uint8Array");
  assert(hash.length === 32, "argon2id hash should be 32 bytes");

  // Deterministic: same input -> same output
  const hash2 = crypto.argon2id(password, salt, 1, 64, 1, 32);
  assert(constantTimeEqual(hash, hash2), "argon2id should be deterministic");

  // Different password -> different hash
  const hash3 = crypto.argon2id(new TextEncoder().encode("other"), salt, 1, 64, 1, 32);
  assert(!constantTimeEqual(hash, hash3), "different password should produce different hash");

  // Input validation
  try { crypto.argon2id(password, salt, 0, 64, 1, 32); assert(false, "timeCost=0 should throw"); }
  catch (_) { assert(true, "timeCost=0 throws"); }

  try { crypto.argon2id(password, salt, 1, 4, 1, 32); assert(false, "memoryCost=4 should throw"); }
  catch (_) { assert(true, "memoryCost too low throws"); }

  try { crypto.argon2id(password, new Uint8Array(4), 1, 64, 1, 32); assert(false, "short salt should throw"); }
  catch (_) { assert(true, "short salt throws"); }

  console.log("  Argon2id: OK");
})();

// ── PBKDF2 Validation ────────────────────────────────────────────

section("PBKDF2 Validation");

(() => {
  // Input validation
  try { crypto.pbkdf2Sha512("pass", "salt", 0, 32); assert(false, "iterations=0 should throw"); }
  catch (_) { assert(true, "iterations=0 throws"); }

  try { crypto.pbkdf2Sha512("pass", "salt", 1, 0); assert(false, "dkLen=0 should throw"); }
  catch (_) { assert(true, "dkLen=0 throws"); }

  try { crypto.pbkdf2Sha512("pass", "salt", -1, 32); assert(false, "iterations=-1 should throw"); }
  catch (_) { assert(true, "iterations=-1 throws"); }

  // Basic round-trip
  const dk = crypto.pbkdf2Sha512("password", "salt", 1, 64);
  assert(dk instanceof Uint8Array && dk.length === 64, "pbkdf2 should return 64 bytes");

  console.log("  PBKDF2 validation: OK");
})();

// ── toBytes normalization ─────────────────────────────────────────

section("toBytes normalization");

(() => {
  // String
  const a = toBytes("hello");
  assert(a instanceof Uint8Array, "string -> Uint8Array");
  assert(a.length === 5, "string length correct");

  // Array
  const b = toBytes([1, 2, 3]);
  assert(b instanceof Uint8Array, "array -> Uint8Array");
  assert(b[0] === 1 && b[1] === 2 && b[2] === 3, "array values correct");

  // Uint8Array passthrough
  const c = new Uint8Array([4, 5]);
  assert(toBytes(c) === c, "Uint8Array should pass through");

  // ArrayBuffer
  const abuf = new ArrayBuffer(3);
  new Uint8Array(abuf).set([10, 20, 30]);
  const d = toBytes(abuf);
  assert(d instanceof Uint8Array && d[0] === 10 && d[1] === 20 && d[2] === 30, "ArrayBuffer should convert");

  // ArrayBuffer view
  const buf = new ArrayBuffer(4);
  new Uint8Array(buf)[0] = 42;
  const e = toBytes(new DataView(buf));
  assert(e instanceof Uint8Array && e[0] === 42, "ArrayBuffer view should convert");

  // Unsupported type
  try {
    toBytes(123);
    assert(false, "number should throw");
  } catch (_) {
    assert(true, "number throws");
  }

  console.log("  toBytes: OK");
})();

// ── Summary ───────────────────────────────────────────────────────

// Wait for async tests to complete before printing summary
function printSummary() {
  if (!asyncDone) { setTimeout(printSummary, 100); return; }
  console.log(`\n═══════════════════════════════════════`);
  console.log(`  ${passed} passed, ${failed} failed`);
  console.log(`═══════════════════════════════════════\n`);
  process.exit(failed > 0 ? 1 : 0);
}
setTimeout(printSummary, 100);
