/**
 * prove.js — Scenario runner for PrescriptionValidation circuit
 * Runs 7 test scenarios covering correctness, security, and edge cases.
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
    console.log(bold("  PrescriptionValidation — Scenario Test Suite (7 cases)  "));
    console.log(bold("══════════════════════════════════════════════════════════"));
    console.log();

    // Pre-compute Poseidon hashes
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const credHash     = F.toObject(poseidon([BigInt(123), BigInt(456)])).toString(); // H(123, 456)
    const srcHash      = F.toObject(poseidon([BigInt(1)])).toString();                // H(1)  — hospital

    const vKey = JSON.parse(fs.readFileSync(VK_PATH));

    let passed = 0;
    const report = [];
    const proofCache = {}; // reused by S6 and S7

    // ── S1: Valid baseline ─────────────────────────────────────────────────
    {
        const id   = "S1";
        const name = "Valid baseline — accept prescription";
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            authorizedAction: "1", sourceId: "1",
            dataAge: "30", allergyClassId: "2", medicationClassId: "5",
            doctorCredentialHash: credHash, trustedSourceHash: srcHash,
            requiredAction: "1", deltaMax: "90", outcome: "1"
        });
        const verifyOk = r.ok && await snarkjs.groth16.verify(vKey, r.publicSignals, r.proof);
        const ok = r.ok === true && verifyOk === true;
        if (ok) { passed++; proofCache[id] = r; }
        printResult(id, name, ok, r.ok, verifyOk, r.error);
        report.push({ id, name, expectProof: true, expectVerify: true, result: ok });
    }

    // ── S2: Invalid credential ─────────────────────────────────────────────
    {
        const id   = "S2";
        const name = "Invalid credential — forged doctorSecret";
        // doctorSecret=999 does not match credHash=H(123,456) → constraint fails
        const r = await tryProve({
            doctorId: "123", doctorSecret: "999",
            authorizedAction: "1", sourceId: "1",
            dataAge: "30", allergyClassId: "2", medicationClassId: "5",
            doctorCredentialHash: credHash, trustedSourceHash: srcHash,
            requiredAction: "1", deltaMax: "90", outcome: "1"
        });
        const verifyOk = false; // proof not generated
        const ok = r.ok === false; // expect failure
        if (ok) passed++;
        printResult(id, name, ok, r.ok, verifyOk, r.error);
        report.push({ id, name, expectProof: false, expectVerify: false, result: ok });
    }

    // ── S3: Untrusted source ───────────────────────────────────────────────
    {
        const id   = "S3";
        const name = "Untrusted source — sourceId not in governance registry";
        // sourceId=99 → H(99) ≠ srcHash=H(1) → constraint fails
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            authorizedAction: "1", sourceId: "99",
            dataAge: "30", allergyClassId: "2", medicationClassId: "5",
            doctorCredentialHash: credHash, trustedSourceHash: srcHash,
            requiredAction: "1", deltaMax: "90", outcome: "1"
        });
        const verifyOk = false;
        const ok = r.ok === false;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, verifyOk, r.error);
        report.push({ id, name, expectProof: false, expectVerify: false, result: ok });
    }

    // ── S4: Freshness violation ────────────────────────────────────────────
    {
        const id   = "S4";
        const name = "Freshness violation — dataAge exceeds Δmax";
        // dataAge=100 > deltaMax=90 → freshOk=0 → computedOutcome=0 ≠ outcome=1 → fails
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            authorizedAction: "1", sourceId: "1",
            dataAge: "100", allergyClassId: "2", medicationClassId: "5",
            doctorCredentialHash: credHash, trustedSourceHash: srcHash,
            requiredAction: "1", deltaMax: "90", outcome: "1"
        });
        const verifyOk = false;
        const ok = r.ok === false;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, verifyOk, r.error);
        report.push({ id, name, expectProof: false, expectVerify: false, result: ok });
    }

    // ── S5a: Contraindication — honest reject ──────────────────────────────
    {
        const id   = "S5a";
        const name = "Contraindication — reject outcome proved correctly";
        // allergyClass=medicationClass=2 → noContraindication=0 → computedOutcome=0
        // prover declares outcome=0 (honest) → constraint 0===0 passes
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            authorizedAction: "1", sourceId: "1",
            dataAge: "30", allergyClassId: "2", medicationClassId: "2",
            doctorCredentialHash: credHash, trustedSourceHash: srcHash,
            requiredAction: "1", deltaMax: "90", outcome: "0"
        });
        const verifyOk = r.ok && await snarkjs.groth16.verify(vKey, r.publicSignals, r.proof);
        const ok = r.ok === true && verifyOk === true;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, verifyOk, r.error);
        report.push({ id, name, expectProof: true, expectVerify: true, result: ok });
    }

    // ── S5b: Outcome integrity — lying about contraindication ─────────────
    {
        const id   = "S5b";
        const name = "Outcome integrity — approve attempt despite contraindication";
        // same contraindication as S5a, but prover lies: outcome=1
        // computedOutcome=0 ≠ outcome=1 → constraint fails
        const r = await tryProve({
            doctorId: "123", doctorSecret: "456",
            authorizedAction: "1", sourceId: "1",
            dataAge: "30", allergyClassId: "2", medicationClassId: "2",
            doctorCredentialHash: credHash, trustedSourceHash: srcHash,
            requiredAction: "1", deltaMax: "90", outcome: "1"
        });
        const verifyOk = false;
        const ok = r.ok === false;
        if (ok) passed++;
        printResult(id, name, ok, r.ok, verifyOk, r.error);
        report.push({ id, name, expectProof: false, expectVerify: false, result: ok });
    }

    // ── S6: Replay / substitution — tampered public signals ───────────────
    {
        const id   = "S6";
        const name = "Replay / substitution — tampered public signals";
        const base = proofCache["S1"];
        if (!base) {
            console.log(`  ${red("SKIP")}  ${id} — S1 proof not available\n`);
        } else {
            // Flip the outcome bit in public signals (last element)
            const tampered = [...base.publicSignals];
            tampered[tampered.length - 1] = tampered[tampered.length - 1] === "1" ? "0" : "1";
            const verifyOk = await snarkjs.groth16.verify(vKey, tampered, base.proof);
            const ok = verifyOk === false; // expect verify to fail
            if (ok) passed++;
            printResult(id, name, ok, true, verifyOk, null);
            report.push({ id, name, expectProof: true, expectVerify: false, result: ok });
        }
    }

    // ── S7: Policy update — wrong verification key ─────────────────────────
    {
        const id   = "S7";
        const name = "Policy update — proof verified against wrong verification key";
        const base = proofCache["S1"];
        if (!base) {
            console.log(`  ${red("SKIP")}  ${id} — S1 proof not available\n`);
        } else {
            // Corrupt vKey by flipping last digits of IC[0][0]
            const badVkey = JSON.parse(JSON.stringify(vKey));
            const orig = badVkey.IC[0][0];
            badVkey.IC[0][0] = orig.slice(0, -6) + "000000";
            const verifyOk = await snarkjs.groth16.verify(badVkey, base.publicSignals, base.proof);
            const ok = verifyOk === false; // expect verify to fail
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
