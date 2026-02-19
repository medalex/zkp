# ZKP Prescription Validation

Zero-knowledge proof implementation of a privacy-preserving prescription validation circuit using **Groth16** over the **BN128** curve.

---

## Overview

This repository contains a complete ZKP pipeline for validating medical prescriptions without revealing patient or doctor data on-chain. The system implements the semantic satisfaction relation from the paper's formal model:

```
M, I |= Rx(d, p, m)  ⟺  Valid(I) ∧ Au(I, prescribe) ∧ ¬Ct(p, m)
```

where `Valid(I)` is defined as:

```
Valid(I)  ⟺  (t_now − t_s) < Δmax  ∧  Auth(cred)  ∧  src ∈ S_trusted
```

The prover demonstrates that a prescription is valid — credentials are authentic, data is fresh, the action is authorized, and no contraindication exists — **without revealing** the doctor's identity, the patient's allergy profile, or the medication details.

---

## Privacy Model

| Signal | Visibility | Semantics |
|--------|-----------|-----------|
| `doctorCredentialHash` | **public** | Poseidon hash of doctor credentials: H(doctorId, doctorSecret) |
| `trustedSourceHash` | **public** | Poseidon hash of data source: H(sourceId) |
| `requiredAction` | **public** | Governance policy parameter (prescribe = 1) |
| `deltaMax` | **public** | Maximum allowed data age in days (e.g. 90) |
| `outcome` | **public** | Binary result: 1 = accept, 0 = reject |
| `doctorId` | **private** | Doctor identity — never revealed |
| `doctorSecret` | **private** | Doctor credential secret — never revealed |
| `allergyClassId` | **private** | Patient's drug allergy class — never revealed |
| `medicationClassId` | **private** | Prescribed drug class — never revealed |
| `dataAge` | **private** | Age of clinical data in days — never revealed |
| `sourceId` | **private** | Data source identifier — never revealed |
| `authorizedAction` | **private** | Action code performed — never revealed |

Only the 5 public signals are visible to the on-chain verifier. All private inputs remain in the witness and are never transmitted.

---

## Circuit Design

The circuit ([prescription.circom](prescription.circom)) performs five checks:

**Check 1 — Auth(cred):** Verifies the doctor's credentials via Poseidon hash.
```
Poseidon(doctorId, doctorSecret) === doctorCredentialHash
```

**Check 2 — src ∈ S_trusted:** Verifies the data source is governance-approved.
```
Poseidon(sourceId) === trustedSourceHash
```

**Check 3 — Data freshness:** Verifies clinical data is not stale.
```
dataAge < deltaMax
```

**Check 4 — Au(I, prescribe):** Verifies the action is authorized.
```
authorizedAction === requiredAction
```

**Check 5 — ¬Ct(p, m):** Verifies no contraindication between allergy and medication drug classes using the is-zero gadget.
```
allergyClassId ≠ medicationClassId
```

**Final composition:**
```
computedOutcome = freshOk * noContraindication
computedOutcome === outcome
```

### Circuit Statistics

| Parameter | Value |
|-----------|-------|
| Proving system | Groth16 |
| Curve | BN128 |
| Non-linear constraints | 495 |
| Linear constraints | 479 |
| Total constraints | 974 |
| Wires | 982 |
| Public inputs | 5 |
| Private inputs | 7 |
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
├── prescription.circom          # Circuit source (Circom 2.0)
├── ceremony.js                  # Reproducible trusted setup script
├── package.json                 # Node.js dependencies (snarkjs, circomlibjs)
├── .gitignore
│
├── verification_key.json        # Public verification key (Groth16/BN128)
├── PrescriptionVerifier.sol     # Solidity on-chain verifier contract
├── ceremony_log.txt             # Full ceremony transcript
│
├── proof.json                   # Example ZK proof (pi_a, pi_b, pi_c)
├── public.json                  # Corresponding public signals
├── input.json                   # Example witness input (test data)
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
- [circom](https://github.com/iden3/circom/releases) binary (place as `circom.exe` on Windows or `circom` on Linux/macOS)

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
5. Compute Poseidon hashes for test inputs
6. Generate a witness and proof
7. Verify the proof
8. Export `PrescriptionVerifier.sol`
9. Write the full log to `ceremony_log.txt`

### Generating a Proof Manually

```bash
# 1. Prepare input.json with your values
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

The included [proof.json](proof.json) was generated for the following scenario:
- Doctor ID: `123`, secret: `456` (credential hash committed on-chain)
- Data source: hospital (`sourceId = 1`, hash committed on-chain)
- Data age: 30 days (within Δmax = 90 days)
- Allergy class: 2 (beta-lactam), Medication class: 5 (antidiabetic) — **no contraindication**
- Outcome: `1` (accept)

Verification result: ✅ `Proof valid: true`

---

## On-Chain Verification

[PrescriptionVerifier.sol](PrescriptionVerifier.sol) is the auto-generated Solidity verifier. Deploy it to any EVM-compatible chain and call:

```solidity
verifyProof(pA, pB, pC, pubSignals)
// returns true if the proof is valid
```

The `pubSignals` array corresponds to:
```
[doctorCredentialHash, trustedSourceHash, requiredAction, deltaMax, outcome]
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [snarkjs](https://github.com/iden3/snarkjs) | 0.7.6 | Trusted setup, proof generation and verification |
| [circomlibjs](https://github.com/iden3/circomlibjs) | latest | Poseidon hash computation in JavaScript |
| [circomlib](https://github.com/iden3/circomlib) | latest | Poseidon and LessThan circuit templates |
