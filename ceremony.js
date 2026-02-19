/**
 * Trusted Setup Ceremony for PrescriptionValidation circuit
 * Groth16 proving system, bn128 curve
 *
 * Phase 1 (Powers of Tau) — универсальная, не зависит от схемы
 * Phase 2 (circuit-specific) — привязана к prescription.r1cs
 */

const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const LOG_FILE = "ceremony_log.txt";
const BUILD_DIR = "build";

// ─── helpers ────────────────────────────────────────────────────────────────

const lines = [];

function log(msg = "") {
    console.log(msg);
    lines.push(msg);
}

function section(title) {
    const bar = "═".repeat(60);
    log("");
    log(bar);
    log(`  ${title}`);
    log(bar);
}

function save() {
    fs.writeFileSync(LOG_FILE, lines.join("\n") + "\n");
}

function formatKey(obj) {
    // print JSON but truncate very long arrays to 4 elements + "..."
    return JSON.stringify(obj, (_k, v) => {
        if (Array.isArray(v) && v.length > 6) {
            return [...v.slice(0, 4), `... (${v.length - 4} more)`];
        }
        return v;
    }, 2);
}

// ─── main ────────────────────────────────────────────────────────────────────

async function main() {
    log("TRUSTED SETUP CEREMONY — PrescriptionValidation");
    log(`Date: ${new Date().toISOString()}`);
    log(`snarkjs version: ${require("./node_modules/snarkjs/package.json").version}`);

    if (!fs.existsSync(BUILD_DIR)) fs.mkdirSync(BUILD_DIR);

    // ────────────────────────────────────────────────────────────────────────
    // STEP 1: Compile the circuit
    // ────────────────────────────────────────────────────────────────────────
    section("STEP 1 — Compile circuit (circom → .r1cs + .wasm + .sym)");

    const circomBin = path.resolve("circom.exe");
    const circomCmd = `"${circomBin}" prescription.circom --r1cs --wasm --sym -o ${BUILD_DIR}`;
    log(`Command: ${circomCmd}`);
    try {
        const out = execSync(circomCmd, { encoding: "utf8" });
        log(out.trim());
    } catch (e) {
        log(e.stdout || "");
        log("STDERR: " + (e.stderr || ""));
        if (!fs.existsSync(`${BUILD_DIR}/prescription.r1cs`)) {
            log("ERROR: Compilation failed. Aborting.");
            save();
            process.exit(1);
        }
    }

    const r1csInfo = await snarkjs.r1cs.info(`${BUILD_DIR}/prescription.r1cs`);
    log("");
    log("R1CS statistics:");
    log(`  Curve:                ${r1csInfo.curveName}`);
    log(`  # wires:              ${r1csInfo.nVars}`);
    log(`  # constraints:        ${r1csInfo.nConstraints}`);
    log(`  # public inputs:      ${r1csInfo.nPubInputs}`);
    log(`  # private inputs:     ${r1csInfo.nPrvInputs}`);
    log(`  # public outputs:     ${r1csInfo.nOutputs}`);

    // ────────────────────────────────────────────────────────────────────────
    // STEP 2: Powers of Tau — Phase 1
    // ────────────────────────────────────────────────────────────────────────
    section("STEP 2 — Powers of Tau: Phase 1");

    log("2a. powersoftau new bn128 12  →  pot12_0000.ptau");
    log("    (2^12 = 4096 constraints max)");
    await snarkjs.powersOfTau.newAccumulator(
        await snarkjs.curves.getCurveFromName("bn128"),
        12,
        `${BUILD_DIR}/pot12_0000.ptau`
    );
    log("    Done.");

    log("");
    log("2b. contribute (Contributor-1)  →  pot12_0001.ptau");
    const contrib1 = await snarkjs.powersOfTau.contribute(
        `${BUILD_DIR}/pot12_0000.ptau`,
        `${BUILD_DIR}/pot12_0001.ptau`,
        "Contributor-1",
        "entropy-phrase-alpha-1234"   // детерминированная энтропия для воспроизводимости
    );
    log(`    Contribution hash: ${contrib1}`);

    log("");
    log("2c. contribute (Contributor-2)  →  pot12_0002.ptau");
    const contrib2 = await snarkjs.powersOfTau.contribute(
        `${BUILD_DIR}/pot12_0001.ptau`,
        `${BUILD_DIR}/pot12_0002.ptau`,
        "Contributor-2",
        "entropy-phrase-beta-5678"
    );
    log(`    Contribution hash: ${contrib2}`);

    log("");
    log("2d. verify accumulator (pot12_0002.ptau)");
    const ptauValid = await snarkjs.powersOfTau.verify(`${BUILD_DIR}/pot12_0002.ptau`);
    log(`    Valid: ${ptauValid}`);

    log("");
    log("2e. prepare phase2  →  pot12_final.ptau");
    await snarkjs.powersOfTau.preparePhase2(
        `${BUILD_DIR}/pot12_0002.ptau`,
        `${BUILD_DIR}/pot12_final.ptau`
    );
    log("    Done.");

    // ────────────────────────────────────────────────────────────────────────
    // STEP 3: Groth16 Setup — Phase 2 (circuit-specific)
    // ────────────────────────────────────────────────────────────────────────
    section("STEP 3 — Groth16 Setup: Phase 2 (circuit-specific)");

    log("3a. groth16 setup  →  prescription_0000.zkey");
    await snarkjs.zKey.newZKey(
        `${BUILD_DIR}/prescription.r1cs`,
        `${BUILD_DIR}/pot12_final.ptau`,
        `${BUILD_DIR}/prescription_0000.zkey`
    );
    log("    Done.");

    log("");
    log("3b. zkey contribute (Contributor-1)  →  prescription_0001.zkey");
    const zkeyC1 = await snarkjs.zKey.contribute(
        `${BUILD_DIR}/prescription_0000.zkey`,
        `${BUILD_DIR}/prescription_0001.zkey`,
        "Contributor-1",
        "zkey-entropy-alpha-1234"
    );
    log(`    Contribution hash: ${Buffer.from(zkeyC1).toString("hex").slice(0, 64)}...`);

    log("");
    log("3c. zkey contribute (Contributor-2)  →  prescription_final.zkey");
    const zkeyC2 = await snarkjs.zKey.contribute(
        `${BUILD_DIR}/prescription_0001.zkey`,
        `${BUILD_DIR}/prescription_final.zkey`,
        "Contributor-2",
        "zkey-entropy-beta-5678"
    );
    log(`    Contribution hash: ${Buffer.from(zkeyC2).toString("hex").slice(0, 64)}...`);

    log("");
    log("3d. verify zkey");
    const zkeyValid = await snarkjs.zKey.verifyFromR1cs(
        `${BUILD_DIR}/prescription.r1cs`,
        `${BUILD_DIR}/pot12_final.ptau`,
        `${BUILD_DIR}/prescription_final.zkey`
    );
    log(`    Valid: ${zkeyValid}`);

    log("");
    log("3e. export verification key  →  verification_key.json");
    const vKey = await snarkjs.zKey.exportVerificationKey(
        `${BUILD_DIR}/prescription_final.zkey`
    );
    fs.writeFileSync("verification_key.json", JSON.stringify(vKey, null, 2));
    log("    Done.");
    log("");
    log("Verification key (summary):");
    log(formatKey(vKey));

    // ────────────────────────────────────────────────────────────────────────
    // STEP 4: Compute public inputs (Poseidon hashes)
    // ────────────────────────────────────────────────────────────────────────
    section("STEP 4 — Compute public inputs for test witness");

    const { buildPoseidon } = require("circomlibjs");
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const doctorId     = BigInt("123");
    const doctorSecret = BigInt("456");
    const sourceId     = BigInt("1");

    const credHash = F.toObject(poseidon([doctorId, doctorSecret]));
    const srcHash  = F.toObject(poseidon([sourceId]));

    log(`doctorId     = ${doctorId}`);
    log(`doctorSecret = ${doctorSecret}`);
    log(`sourceId     = ${sourceId}`);
    log(`doctorCredentialHash = ${credHash}`);
    log(`trustedSourceHash    = ${srcHash}`);

    const input = {
        doctorId:             doctorId.toString(),
        doctorSecret:         doctorSecret.toString(),
        authorizedAction:     "1",
        sourceId:             sourceId.toString(),
        dataAge:              "30",
        allergyClassId:       "2",
        medicationClassId:    "5",
        doctorCredentialHash: credHash.toString(),
        trustedSourceHash:    srcHash.toString(),
        requiredAction:       "1",
        deltaMax:             "90",
        outcome:              "1"
    };

    fs.writeFileSync("input.json", JSON.stringify(input, null, 2));
    log("");
    log("input.json saved.");
    log(JSON.stringify(input, null, 2));

    // ────────────────────────────────────────────────────────────────────────
    // STEP 5: Generate witness
    // ────────────────────────────────────────────────────────────────────────
    section("STEP 5 — Generate witness");

    const wasmPath = `${BUILD_DIR}/prescription_js/prescription.wasm`;
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasmPath,
        `${BUILD_DIR}/prescription_final.zkey`
    );

    fs.writeFileSync("proof.json", JSON.stringify(proof, null, 2));
    fs.writeFileSync("public.json", JSON.stringify(publicSignals, null, 2));

    log("Witness generated and proof computed.");
    log("");
    log("Public signals:");
    log(JSON.stringify(publicSignals, null, 2));
    log("");
    log("Proof (summary):");
    log(formatKey(proof));

    // ────────────────────────────────────────────────────────────────────────
    // STEP 6: Verify proof
    // ────────────────────────────────────────────────────────────────────────
    section("STEP 6 — Verify proof");

    const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    log(`Proof valid: ${isValid}`);

    if (!isValid) {
        log("ERROR: Proof verification failed!");
    } else {
        log("SUCCESS: Zero-knowledge proof is valid.");
    }

    // ────────────────────────────────────────────────────────────────────────
    // STEP 7: Export Solidity verifier
    // ────────────────────────────────────────────────────────────────────────
    section("STEP 7 — Export Solidity verifier");

    const templatePath = path.join(
        path.dirname(require.resolve("snarkjs")),
        "../templates/verifier_groth16.sol.ejs"
    );
    const solidityCode = await snarkjs.zKey.exportSolidityVerifier(
        `${BUILD_DIR}/prescription_final.zkey`,
        { groth16: fs.readFileSync(templatePath, "utf8") }
    );
    fs.writeFileSync("PrescriptionVerifier.sol", solidityCode);
    log("PrescriptionVerifier.sol written.");

    // ────────────────────────────────────────────────────────────────────────
    // Summary
    // ────────────────────────────────────────────────────────────────────────
    section("CEREMONY COMPLETE — Output files");

    const files = [
        ["build/prescription.r1cs",       "Compiled R1CS constraint system"],
        ["build/prescription.wasm",        "WebAssembly witness generator (inside prescription_js/)"],
        ["build/pot12_final.ptau",         "Phase 1 Powers of Tau (universal)"],
        ["build/prescription_final.zkey",  "Phase 2 proving key (circuit-specific)"],
        ["verification_key.json",          "Verification key (public)"],
        ["input.json",                     "Test input / witness data"],
        ["proof.json",                     "Generated ZK proof"],
        ["public.json",                    "Public signals"],
        ["PrescriptionVerifier.sol",       "Solidity on-chain verifier"],
        [LOG_FILE,                         "This ceremony log"],
    ];

    for (const [f, desc] of files) {
        log(`  ${f.padEnd(42)} ${desc}`);
    }

    log("");
    log("Ceremony finished at: " + new Date().toISOString());

    save();
    console.log(`\nLog written to: ${LOG_FILE}`);
}

main().catch(e => {
    console.error(e);
    process.exit(1);
});
