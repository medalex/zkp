/**
 * prove.js — Scenario runner for PrescriptionValidation circuit (v2)
 * Runs 8 test scenarios covering correctness, security, and edge cases.
 *
 * Matches Table VIII of the paper (8/8 scenarios).
 * Public inputs: stmtHash, outcome, tsAnchor, nonce, deltaMax, theta, requiredAction
 *
 * Usage: node prove.js
 */

const snarkjs = require("snarkjs");
const fs      = require("fs");
const { buildPoseidon } = require("circomlibjs");

const WASM_PATH = "build/prescription_js/prescription.wasm";
const ZKEY_PATH = "build/prescription_final.zkey";
const VK_PATH   = "verification_key.json";

// ── terminal helpers ───────────────────────────────────────────────────────
const green  = (s) => `\x1b[32m${s}\x1b[0m`;
const red    = (s) => `\x1b[31m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
const bold   = (s) => `\x1b[1m${s}\x1b[0m`;

function printResult(id, name, ok, proofOk, verifyOk, error) {
    const tag = ok ? green("✓ PASS") : red("✗ FAIL");
    console.log(`  ${tag}  ${bold(id)} — ${name}`);
    console.log(`         proof generated: ${proofOk ? green("true") : red("false")}  |  verified: ${verifyOk ? green("true") : red("false")}`);
    if (error) console.log(`         ${yellow("error:")} ${error.slice(0, 120)}`);
    console.log();
}

// ── attempt proof + verify, catch constraint errors ───────────────────────
async function tryProve(input) {
    try {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input, WASM_PATH, ZKEY_PATH
        );
        return { ok: true, proof, publicSignals };
    } catch (e) {
        return { ok: false, error: e.message || String(e) };
    }
}

// ── main ───────────────────────────────────────────────────────────────────
async function main() {
    console.log();
    console.log(bold("══════════════════════════════════════════════════════════"));
    console.log(bold("  PrescriptionValidation — Scenario Test Suite (8 cases)  "));
    console.log(bold("══════════════════════════════════════════════════════════"));
    console.log();

    // ── Pre-compute stmtHash for the Metformin running case  (Eq. 14) ─────
    // stmtHash = Poseidon(doctorId, doctorSecret, patientId, medicationId,
    //                     sourceId, policyVersion, nonce)
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Base identity parameters — used for the correct stmtHash
    const BASE = {
        doctorId: "123", doctorSecret: "456",
        patientId: "1",  medicationId: "5",
        sourceId: "1",   policyVersion: "1",
        nonce: "42"
    };

    const stmtHash = F.toObject(
        poseidon([
            BigInt(BASE.doctorId),     BigInt(BASE.doctorSecret),
            BigInt(BASE.patientId),    BigInt(BASE.medicationId),
            BigInt(BASE.sourceId),     BigInt(BASE.policyVersion),
            BigInt(BASE.nonce)
        ])
    ).toString();

    // Governance / clinical policy constants (public)
    const DELTA_MAX      = "90";  // Δmax = 90 days
    const THETA          = "30";  // θ = 30 mL/min/1.73m²  (eGFR threshold for Metformin)
    const TS_ANCHOR      = "90";  // coarse-grained time anchor for auditability
    const REQUIRED_ACTION = "1";  // prescribe = 1

    const vKey = JSON.parse(fs.readFileSync(VK_PATH));

    let passed = 0;
    const report = [];
    const proofCache = {}; // S1 proof reused by S6 and S7

    // ── S1: Valid baseline ─────────────────────────────────────────────────
    // All conditions satisfied: correct stmtHash, fresh data (dataAge=30 ≤ Δmax=90),
    // authorized action, no contraindication (allergyClass=2 ≠ medicationClass=5),
    // eGFR=45 ≥ θ=30 (pol_ok=1).  [Section VII-B, Table VIII]
    {
        const id   = "S1";
        const name = "Valid baseline — accept Metformin prescription (eGFR=45 ≥ θ=30)";
        const r = await tryProve({
            // Private inputs (11)
            doctorId: "123", doctorSecret: "456",
            patientId: "1",  medicationId: "5",
            sourceId: "1",   policyVersion: "1",
            dataAge: "30",   authorizedAction: "1",
            allergyClassId: "2", medicationClassId: "5",
            clinVal: "45",   // eGFR = 45 ≥ θ = 30  →  pol_ok = 1
            // Public inputs (7)
            stmtHash, outcome: "1",
            tsAnchor: TS_ANCHOR, nonce: BASE.nonce,
            deltaMax: DELTA_MAX, theta: THETA,
            requiredAction: REQUIRED_ACTION
        });
        const verifyOk = r.ok && await snarkjs.groth16.verify(vKey, r.publicSignals, r.proof);
        const ok = r.ok === true && verifyOk === true;
        if (ok) { passed++; proofCache[id] = r; }
        printResult(id, name, ok, r.ok, verifyOk, r.error);
        report.push({ id, name, expectProof: true, expectVerify: true, result: ok });
    }

    // ── S2: Invalid credential ─────────────────────────────────────────────
    // doctorSecret=999 does not match stmtHash=H(...,456,...).
    // Circuit computes H(123,999,...,42) ≠ stmtHash → hard constraint fails.
    // Verifies Auth(cred) soundness via stmtHash binding.  [Section VII-B]
    {
        const id   = "S2";
        const name = "Invalid credential — forged doctorSecret";
        const r = await tryProve({
            doctorId: "123", doctorSecret: "999",   // tampered: 999 ≠ 456
            patientId: "1",  medicationId: "5",
            sourceId: "1",   policyVersion: "1",
            dataAge: "30",   authorizedAction: "1",
            allergyClassId: "2", medicationClassId: "5",
            clinVal: "45",
            stmtHash,   // correct hash: H(123, 456, ...) — mismatch detected
            outcome: "1", tsAnchor: TS_ANCHOR, nonce: BASE.nonce,
            deltaMax: DELTA_MAX, theta: THETA,
            requiredAction: REQUIRED_ACTION
        });
        const ok = r.ok === false;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, false, r.error);
        report.push({ id, name, expectProof: false, expectVerify: false, result: ok });
    }

    // ── S3: Untrusted source ───────────────────────────────────────────────
    // sourceId=99 is not in S_trusted. Circuit computes H(...,99,...,42) ≠ stmtHash.
    // Verifies src ∈ S_trusted enforcement via stmtHash binding.  [Section VII-B]
    {
        const id   = "S3";
        const name = "Untrusted source — sourceId not in governance registry";
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            patientId: "1",  medicationId: "5",
            sourceId: "99",  policyVersion: "1",   // tampered: 99 ∉ S_trusted
            dataAge: "30",   authorizedAction: "1",
            allergyClassId: "2", medicationClassId: "5",
            clinVal: "45",
            stmtHash,   // correct hash: H(..., 1, ...) — mismatch detected
            outcome: "1", tsAnchor: TS_ANCHOR, nonce: BASE.nonce,
            deltaMax: DELTA_MAX, theta: THETA,
            requiredAction: REQUIRED_ACTION
        });
        const ok = r.ok === false;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, false, r.error);
        report.push({ id, name, expectProof: false, expectVerify: false, result: ok });
    }

    // ── S4: Freshness violation ────────────────────────────────────────────
    // dataAge=100 > Δmax=90  →  LessEqThan sets freshOk=0
    // validCtx=0  →  computedOutcome=0 ≠ outcome=1  →  final constraint fails.
    {
        const id   = "S4";
        const name = "Freshness violation — dataAge exceeds Δmax";
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            patientId: "1",  medicationId: "5",
            sourceId: "1",   policyVersion: "1",
            dataAge: "100",  authorizedAction: "1",   // 100 > 90 → stale
            allergyClassId: "2", medicationClassId: "5",
            clinVal: "45",
            stmtHash, outcome: "1",
            tsAnchor: TS_ANCHOR, nonce: BASE.nonce,
            deltaMax: DELTA_MAX, theta: THETA,
            requiredAction: REQUIRED_ACTION
        });
        const ok = r.ok === false;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, false, r.error);
        report.push({ id, name, expectProof: false, expectVerify: false, result: ok });
    }

    // ── S5a: Contraindication — honest reject ──────────────────────────────
    // allergyClassId=medicationClassId=2  →  allergyContra=1, noContra=0
    // clinicalOk=0  →  computedOutcome=0.
    // Prover honestly declares outcome=0  →  0===0 passes.
    // Valid rejection proof is produced and verifiable on-chain.  [Section VII-B]
    {
        const id   = "S5a";
        const name = "Contraindication — reject outcome proved correctly";
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            patientId: "1",  medicationId: "5",
            sourceId: "1",   policyVersion: "1",
            dataAge: "30",   authorizedAction: "1",
            allergyClassId: "2", medicationClassId: "2",  // same class → contraindicated
            clinVal: "45",
            stmtHash, outcome: "0",   // honest: outcome=0 (reject)
            tsAnchor: TS_ANCHOR, nonce: BASE.nonce,
            deltaMax: DELTA_MAX, theta: THETA,
            requiredAction: REQUIRED_ACTION
        });
        const verifyOk = r.ok && await snarkjs.groth16.verify(vKey, r.publicSignals, r.proof);
        const ok = r.ok === true && verifyOk === true;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, verifyOk, r.error);
        report.push({ id, name, expectProof: true, expectVerify: true, result: ok });
    }

    // ── S5b: Outcome integrity — forged accept despite contraindication ────
    // Same contraindication as S5a, but prover lies: outcome=1.
    // computedOutcome=0 ≠ outcome=1  →  final constraint fails.
    // Together with S5a demonstrates outcome integrity (Eq. 23).  [Section VII-B]
    {
        const id   = "S5b";
        const name = "Outcome integrity — approve attempt despite contraindication";
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            patientId: "1",  medicationId: "5",
            sourceId: "1",   policyVersion: "1",
            dataAge: "30",   authorizedAction: "1",
            allergyClassId: "2", medicationClassId: "2",  // contraindication
            clinVal: "45",
            stmtHash, outcome: "1",   // lie: prover claims accept
            tsAnchor: TS_ANCHOR, nonce: BASE.nonce,
            deltaMax: DELTA_MAX, theta: THETA,
            requiredAction: REQUIRED_ACTION
        });
        const ok = r.ok === false;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, false, r.error);
        report.push({ id, name, expectProof: false, expectVerify: false, result: ok });
    }

    // ── S6: Replay / substitution — tampered public signals ───────────────
    // Valid proof π from S1 is reused with outcome flipped (index 1 in pub vector).
    // Groth16 pairing equations are binding over the exact public-input vector;
    // any modification invalidates the proof.  [Section VII-B]
    {
        const id   = "S6";
        const name = "Replay / substitution — tampered public signals";
        const base = proofCache["S1"];
        if (!base) {
            console.log(`  ${red("SKIP")}  ${id} — S1 proof not available\n`);
        } else {
            // pub = [stmtHash(0), outcome(1), tsAnchor(2), nonce(3), deltaMax(4), theta(5), requiredAction(6)]
            // Flip outcome at index 1
            const tampered = [...base.publicSignals];
            tampered[1] = tampered[1] === "1" ? "0" : "1";
            const verifyOk = await snarkjs.groth16.verify(vKey, tampered, base.proof);
            const ok = verifyOk === false;
            if (ok) passed++;
            printResult(id, name, ok, true, verifyOk, null);
            report.push({ id, name, expectProof: true, expectVerify: false, result: ok });
        }
    }

    // ── S7: Policy update — wrong verification key ─────────────────────────
    // Valid proof and public signals from S1 submitted to a verifier with a
    // corrupted vKey (simulating governance circuit revision).
    // vk is bound to the exact circuit; pairing check fails.  [Section VII-B]
    {
        const id   = "S7";
        const name = "Policy update — proof verified against wrong verification key";
        const base = proofCache["S1"];
        if (!base) {
            console.log(`  ${red("SKIP")}  ${id} — S1 proof not available\n`);
        } else {
            const badVkey = JSON.parse(JSON.stringify(vKey));
            const orig = badVkey.IC[0][0];
            badVkey.IC[0][0] = orig.slice(0, -6) + "000000";
            const verifyOk = await snarkjs.groth16.verify(badVkey, base.publicSignals, base.proof);
            const ok = verifyOk === false;
            if (ok) passed++;
            printResult(id, name, ok, true, verifyOk, null);
            report.push({ id, name, expectProof: true, expectVerify: false, result: ok });
        }
    }

    // ── Summary ────────────────────────────────────────────────────────────
    const total = report.length;
    const color = passed === total ? green : red;
    console.log(bold("══════════════════════════════════════════════════════════"));
    console.log(`  Results: ${color(`${passed}/${total} passed`)}`);
    console.log(bold("══════════════════════════════════════════════════════════"));
    console.log();

    fs.writeFileSync("test_results.json", JSON.stringify(report, null, 2));
    console.log("Report saved to test_results.json\n");
}

main().catch(e => { console.error(e); process.exit(1); });
