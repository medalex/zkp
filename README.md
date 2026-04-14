# ZKP Prescription Validation

Zero-knowledge proof implementation of a privacy-preserving prescription validation circuit using **Groth16** over the **BN128** curve.

---

## Overview

This repository contains a complete ZKP pipeline for validating medical prescriptions without revealing patient or doctor data on-chain. The system implements the semantic satisfaction relation from the paper's formal model (Definition 2, Eq. 13):

```
M, Γ |= Rx(d, p, m)  ⟺  M, Γ |= Au(d, prescribe)
                       ∧  M, Γ ⊭ Ct(p, m)
                       ∧  M, Γ |= PolOk(p, m)
```

where context validity is defined as (Definition 1, Eq. 8):

```
Valid(Γ)  ⟺  (t_now − t_s) ≤ Δmax  ∧  Auth(cred)  ∧  src ∈ S_trusted
```

The prover demonstrates that a prescription is valid — credentials are authentic, data is fresh, the action is authorized, no allergy-based contraindication exists, and all clinical policy constraints are satisfied (e.g. eGFR ≥ 30 for Metformin) — **without revealing** the doctor's identity, the patient's allergy profile, the medication details, or any laboratory values.

---

## Privacy Model

A single statement commitment `stmtHash = Poseidon(doctorId, doctorSecret, patientId, medicationId, sourceId, policyVersion, nonce)` binds all identity components on-chain without disclosing them (Eq. 14). Clinical evidence and laboratory values remain exclusively in the private witness.

| Signal | Visibility | Semantics |
|--------|-----------|-----------|
| `stmtHash` | **public** | `H(φ⁺ ‖ policyVersion ‖ nonce)` — commits to the full statement without revealing it |
| `outcome` | **public** | Binary result: 1 = accept, 0 = reject |
| `tsAnchor` | **public** | Coarse-grained time anchor for on-chain auditability |
| `nonce` | **public** | Per-workflow unique value for replay protection |
| `deltaMax` | **public** | Maximum permitted data age in days (governance parameter, e.g. 90) |
| `theta` | **public** | Clinical policy threshold: eGFR ≥ θ for Metformin (e.g. 30 mL/min/1.73m²) |
| `requiredAction` | **public** | Governance policy action code (prescribe = 1) |
| `doctorId` | **private** | Prescriber identity — never revealed |
| `doctorSecret` | **private** | Prescriber credential secret — never revealed |
| `patientId` | **private** | Patient identifier — never revealed |
| `medicationId` | **private** | Medication identifier — never revealed |
| `sourceId` | **private** | Data source identifier — never revealed |
| `policyVersion` | **private** | Governance theory snapshot version — never revealed |
| `dataAge` | **private** | Age of clinical data in days — never revealed |
| `authorizedAction` | **private** | Action code performed — never revealed |
| `allergyClassId` | **private** | Patient's drug allergy class — never revealed |
| `medicationClassId` | **private** | Prescribed drug class — never revealed |
| `clinVal` | **private** | Patient's eGFR value (mL/min/1.73m²) — never revealed |

Only the 7 public signals are visible to the on-chain verifier. All 11 private inputs remain in the witness and are never transmitted.

---

## Circuit Design

The circuit ([prescription.circom](prescription.circom)) decomposes validation into five sub-circuits, each outputting a Boolean flag, composed into a single acceptance decision (Eq. 20–23).

**Sub-circuit 1 — Statement binding** `[Eq. 14]`

Verifies the full identity commitment. Any wrong identity component (doctor, patient, medication, source, or policy version) causes a hash mismatch and rejects the proof.
```
Poseidon(doctorId, doctorSecret, patientId, medicationId,
         sourceId, policyVersion, nonce) === stmtHash
```

**Sub-circuit 2 — `auth_ok`: Au(d, prescribe)** `[Eq. 16]`

Verifies the prescriber is authorized to perform the governance-required action.
```
authorizedAction === requiredAction  →  authOk = 1
```

**Sub-circuit 3 — `fresh_ok`: (t_now − t_s) ≤ Δmax** `[Eq. 18, Definition 1]`

Rejects stale clinical evidence. Uses `LessEqThan` per the paper's ≤ condition.
```
dataAge ≤ deltaMax  →  freshOk = 1
```

**Sub-circuit 4 — `no_contra`: ¬Ct(p, m)** `[Eq. 17, 21]`

Detects allergy-based contraindication via drug class equality using the is-zero gadget.
```
allergyClassId ≠ medicationClassId  →  noContra = 1
```

**Sub-circuit 5 — `pol_ok`: PolOk(p, m)** `[Eq. 19]`

Enforces the governance-approved clinical policy axiom `Pol(Metformin, eGFR, ≥, θ)`. The patient's eGFR (`clinVal`) is kept private; only the threshold `theta` is public.
```
clinVal ≥ theta  →  polOk = 1
```

**Final composition** `[Eq. 20–23]`
```
valid_ctx   = freshOk   * authOk       (Eq. 20)
no_contra   = 1 - allergyContra        (Eq. 21)
clinical_ok = noContra  * polOk        (Eq. 22)
outcome     = valid_ctx * clinical_ok  (Eq. 23)
```

A single failure in any sub-circuit forces `outcome = 0`. The prover cannot misreport the outcome without breaking the final equality constraint.

### Circuit Statistics

| Parameter | Value |
|-----------|-------|
| Proving system | Groth16 |
| Curve | BN128 |
| Total constraints | 1165 |
| Wires | 1180 |
| Public inputs | 7 |
| Private inputs | 11 |
| Proof size | 192 bytes (3 elliptic curve points) |

---

## Trusted Setup Ceremony

The cryptographic parameters were generated via a two-phase trusted setup. The ceremony is fully reproducible by running [ceremony.js](ceremony.js).

### Phase 1 — Powers of Tau (universal)

Generates the structured reference string, independent of the circuit. Two contributors participated:

| Step | Contributor | Output |
|------|------------|--------|
| New accumulator (2¹² = 4096 max constraints) | — | `pot12_0000.ptau` |
| Contribution 1 | Contributor-1 | `pot12_0001.ptau` |
| Contribution 2 | Contributor-2 | `pot12_0002.ptau` |
| Prepare Phase 2 | — | `pot12_final.ptau` |

Phase 1 accumulator verified: ✅ `Valid: true`

### Phase 2 — Circuit-Specific Setup

Binds the structured reference string to `prescription.r1cs`. Two contributors participated:

| Step | Contributor | Output |
|------|------------|--------|
| Groth16 setup | — | `prescription_0000.zkey` |
| Contribution 1 | Contributor-1 | `prescription_0001.zkey` |
| Contribution 2 | Contributor-2 | `prescription_final.zkey` |
| Export verification key | — | `verification_key.json` |

Phase 2 zkey verified: ✅ `Valid: true`

The full ceremony transcript is in [ceremony_log.txt](ceremony_log.txt).

**Security note:** The setup is secure as long as at least one contributor destroyed their randomness (toxic waste). With two independent contributors, a single honest participant is sufficient.

---

## Repository Structure

```
.
├── prescription.circom          # Circuit source (Circom 2.0) — 5 sub-circuits
├── ceremony.js                  # Reproducible trusted setup script
├── prove.js                     # Scenario test runner (8 test cases)
├── package.json                 # Node.js dependencies (snarkjs, circomlibjs)
├── .gitignore
│
├── verification_key.json        # Public verification key (Groth16/BN128)
├── PrescriptionVerifier.sol     # Solidity on-chain verifier contract (auto-generated)
├── ceremony_log.txt             # Full ceremony transcript
│
├── proof.json                   # Example ZK proof (pi_a, pi_b, pi_c)
├── public.json                  # Corresponding public signals
├── input.json                   # Example witness input (Metformin running case)
├── test_results.json            # Machine-readable test results
│
└── build/
    ├── prescription.r1cs        # Compiled R1CS constraint system
    ├── prescription.sym         # Symbol table (signal names)
    ├── prescription_final.zkey  # Phase 2 proving key
    └── prescription_js/
        ├── prescription.wasm    # WebAssembly witness generator
        ├── generate_witness.js  # Witness generation script
        └── witness_calculator.js
```

---

## Reproducing the Ceremony

### Prerequisites

- Node.js ≥ 18
- [circom](https://github.com/iden3/circom/releases) binary — place as `circom.exe` in the project root on Windows, or `circom` on Linux/macOS (listed in `.gitignore`, not committed)

### Steps

```bash
npm install
node ceremony.js
```

This will:
1. Compile `prescription.circom` → `.r1cs`, `.wasm`, `.sym`
2. Run Powers of Tau Phase 1 (2 contributors)
3. Run Groth16 Phase 2 (2 contributors)
4. Export `verification_key.json`
5. Compute `stmtHash = Poseidon(doctorId, doctorSecret, patientId, medicationId, sourceId, policyVersion, nonce)`
6. Generate a witness and proof for the Metformin running case
7. Verify the proof
8. Export `PrescriptionVerifier.sol`
9. Write the full log to `ceremony_log.txt`

### Generating a Proof Manually

```bash
# 1. Prepare input.json with your values (see input.json for the field list)

# 2. Generate witness
node build/prescription_js/generate_witness.js \
     build/prescription_js/prescription.wasm \
     input.json witness.wtns

# 3. Generate proof
npx snarkjs groth16 prove \
     build/prescription_final.zkey witness.wtns \
     proof.json public.json

# 4. Verify proof
npx snarkjs groth16 verify \
     verification_key.json public.json proof.json
```

---

## Example Proof

The included [proof.json](proof.json) was generated for the Metformin running case (Section VII-B of the paper):

| Input | Value | Role |
|-------|-------|------|
| `doctorId` / `doctorSecret` | `123` / `456` | committed in `stmtHash` |
| `patientId` / `medicationId` | `1` / `5` (Metformin) | committed in `stmtHash` |
| `sourceId` / `policyVersion` / `nonce` | `1` / `1` / `42` | committed in `stmtHash` |
| `dataAge` | `30` days | 30 ≤ Δmax=90 → `freshOk = 1` |
| `allergyClassId` / `medicationClassId` | `2` / `5` | 2 ≠ 5 → `noContra = 1` |
| `clinVal` | `45` mL/min/1.73m² | 45 ≥ θ=30 → `polOk = 1` |
| `outcome` | `1` | accept |

Verification result: ✅ `Proof valid: true`

---

## On-Chain Verification

[PrescriptionVerifier.sol](PrescriptionVerifier.sol) is the auto-generated Solidity verifier. Deploy it to any EVM-compatible chain and call:

```solidity
verifyProof(pA, pB, pC, pubSignals)
// returns true if the proof is valid
```

The `pubSignals` array corresponds to (Eq. 25):
```
[stmtHash, outcome, tsAnchor, nonce, deltaMax, theta, requiredAction]
```

The governance layer observes only `(π, pubSignals)`. Sensitive attributes — medication identity, eGFR value, allergy records, and doctor identity — are embedded only within `stmtHash` or remain in the private witness, and are never disclosed on-chain.

---

## Testing

The repository includes a scenario test suite covering all constraints and security properties from Table VIII of the paper.

```bash
node prove.js
```

**8/8 scenarios pass.** Results are written to `test_results.json`.

| ID | Scenario | Proof | Verify | Property verified |
|----|----------|:-----:|:------:|-------------------|
| S1 | Valid baseline (eGFR=45 ≥ θ=30) | ✓ | ✓ | Completeness |
| S2 | Invalid credential (forged doctorSecret) | ✗ | ✗ | Auth(cred) soundness |
| S3 | Untrusted source (sourceId ∉ S_trusted) | ✗ | ✗ | Provenance soundness |
| S4 | Freshness violation (dataAge > Δmax) | ✗ | ✗ | Freshness soundness |
| S5a | Contraindication — honest reject | ✓ | ✓ | Completeness (reject) |
| S5b | Contraindication — forged accept | ✗ | ✗ | Outcome integrity |
| S6 | Replay attack (tampered public signals) | reuse | ✗ | Replay resistance |
| S7 | Policy update (wrong verification key) | reuse | ✗ | Key binding |

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [snarkjs](https://github.com/iden3/snarkjs) | 0.7.6 | Trusted setup, proof generation and verification |
| [circomlibjs](https://github.com/iden3/circomlibjs) | latest | Poseidon hash computation in JavaScript |
| [circomlib](https://github.com/iden3/circomlib) | latest | Poseidon, comparator circuit templates (LessEqThan, GreaterEqThan, IsEqual) |
