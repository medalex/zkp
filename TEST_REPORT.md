# PrescriptionValidation ZKP — Test Execution Report

**Circuit:** `prescription.circom` (Circom 2.0)
**Proving system:** Groth16 / BN128
**Runner:** `node prove.js`
**snarkjs version:** 0.7.6
**Date:** 2026-02-20
**Status: 8/8 PASSED ✓**

---

## Environment

| Parameter | Value |
|-----------|-------|
| Node.js | v18+ |
| snarkjs | 0.7.6 |
| circomlibjs | latest |
| Proving key | `build/prescription_final.zkey` |
| Verification key | `verification_key.json` |
| WASM witness generator | `build/prescription_js/prescription.wasm` |
| Circuit constraints | 974 (495 non-linear, 479 linear) |
| Wires | 982 |
| Public inputs | 5 |
| Private inputs | 7 |

---

## Results Summary

| ID | Scenario | Proof | Verify | Expected | Result |
|----|----------|:-----:|:------:|:--------:|:------:|
| S1 | Valid baseline | ✓ | ✓ | PASS | ✅ PASS |
| S2 | Invalid credential | ✗ | ✗ | FAIL | ✅ PASS |
| S3 | Untrusted source | ✗ | ✗ | FAIL | ✅ PASS |
| S4 | Freshness violation | ✗ | ✗ | FAIL | ✅ PASS |
| S5a | Honest reject (contraindication) | ✓ | ✓ | PASS | ✅ PASS |
| S5b | Forged accept (contraindication) | ✗ | ✗ | FAIL | ✅ PASS |
| S6 | Replay / tampered signals | reuse | ✗ | FAIL | ✅ PASS |
| S7 | Wrong verification key | reuse | ✗ | FAIL | ✅ PASS |

**Total: 8 / 8 passed**

---

## Detailed Results

---

### S1 — Valid Baseline

**Scenario:** All checks satisfied; honest prover with valid credentials, trusted source, fresh data, no contraindication, authorized action.

**Inputs:**

| Signal | Value | Visibility |
|--------|-------|-----------|
| `doctorId` | 123 | private |
| `doctorSecret` | 456 | private |
| `authorizedAction` | 1 | private |
| `sourceId` | 1 | private |
| `dataAge` | 30 | private |
| `allergyClassId` | 2 | private |
| `medicationClassId` | 5 | private |
| `doctorCredentialHash` | Poseidon(123, 456) | public |
| `trustedSourceHash` | Poseidon(1) | public |
| `requiredAction` | 1 | public |
| `deltaMax` | 90 | public |
| `outcome` | 1 | public |

**Execution:**
- Check 1 (Auth): `Poseidon(123, 456) === credHash` → ✓
- Check 2 (Source): `Poseidon(1) === srcHash` → ✓
- Check 3 (Freshness): `30 < 90` → `freshOk = 1` ✓
- Check 4 (Action): `1 - 1 = 0` → ✓
- Check 5 (Contraindication): `5 - 2 ≠ 0` → `noContraindication = 1` ✓
- Final: `computedOutcome = 1 × 1 = 1 === outcome(1)` ✓

**Result:** `proof generated = true` | `Verify(π, pub) = true` | **✅ PASS**

---

### S2 — Invalid Credential

**Scenario:** Prover supplies `doctorSecret = 999` but the on-chain commitment is `Poseidon(123, 456)`. The circuit computes `Poseidon(123, 999)` which does not match — constraint assertion fails at circuit line 76.

**Divergence from S1:** `doctorSecret = 999` (correct value: 456)

**Execution:**
- Check 1 (Auth): `Poseidon(123, 999) ≠ doctorCredentialHash`
- **Constraint failure:** `Assert Failed. Error in template PrescriptionValidation line: 76`
- Witness generation aborted; no proof produced.

**Result:** `proof generated = false` | `verified = false` | **✅ PASS**

---

### S3 — Untrusted Source

**Scenario:** Prover claims `sourceId = 99` (not in the governance-approved trusted set). The on-chain `trustedSourceHash` encodes source ID 1 (hospital). The circuit computes `Poseidon(99) ≠ trustedSourceHash` — constraint fails at line 87.

**Divergence from S1:** `sourceId = 99` (correct value: 1)

**Execution:**
- Check 2 (Source): `Poseidon(99) ≠ trustedSourceHash`
- **Constraint failure:** `Assert Failed. Error in template PrescriptionValidation line: 87`
- Witness generation aborted; no proof produced.

**Result:** `proof generated = false` | `verified = false` | **✅ PASS**

---

### S4 — Freshness Violation

**Scenario:** Clinical data is stale — `dataAge = 100` days exceeds `deltaMax = 90`. The `LessThan(32)` gadget outputs `freshOk = 0`, so `computedOutcome = 0 ≠ outcome(1)` — final constraint fails at line 157.

**Divergence from S1:** `dataAge = 100` (correct value: 30)

**Execution:**
- Check 3 (Freshness): `100 < 90` → `false` → `freshOk = 0`
- Final: `computedOutcome = 0 × 1 = 0 ≠ outcome(1)`
- **Constraint failure:** `Assert Failed. Error in template PrescriptionValidation line: 157`

**Result:** `proof generated = false` | `verified = false` | **✅ PASS**

---

### S5a — Contraindication: Honest Reject

**Scenario:** Patient allergy class equals medication class (`allergyClassId = medicationClassId = 2`). The is-zero gadget detects the match: `noContraindication = 0`, so `computedOutcome = 0`. The prover **honestly** declares `outcome = 0`. Constraint `0 === 0` passes — a valid reject proof is produced.

**Divergence from S1:** `medicationClassId = 2`, `outcome = 0`

**Execution:**
- Check 5 (Contraindication): `2 - 2 = 0` → `isZero = 1` → `noContraindication = 0`
- Final: `computedOutcome = 1 × 0 = 0 === outcome(0)` ✓

**Result:** `proof generated = true` | `Verify(π, pub) = true` | **✅ PASS**

> A ZKP of *rejection* is itself auditable on-chain: the verifier confirms the prescription was correctly refused without learning the patient's allergy details.

---

### S5b — Outcome Integrity: Forged Accept

**Scenario:** Same contraindication as S5a, but the prover attempts to claim `outcome = 1` (accept). The circuit computes `computedOutcome = 0` but the declared `outcome = 1` — constraint `0 === 1` fails at line 157. The prover cannot lie about the outcome.

**Divergence from S1:** `medicationClassId = 2`, `outcome = 1` (forged)

**Execution:**
- Check 5 (Contraindication): `noContraindication = 0`
- Final: `computedOutcome = 0 ≠ outcome(1)`
- **Constraint failure:** `Assert Failed. Error in template PrescriptionValidation line: 157`

**Result:** `proof generated = false` | `verified = false` | **✅ PASS**

---

### S6 — Replay / Substitution Attack

**Scenario:** The valid proof π from S1 is reused without modification. An adversary flips the `outcome` field in the public signals array from `1` to `0`, attempting to claim the prescription was rejected. The Groth16 pairing check binds the proof to the exact public input vector — any change invalidates it.

**Setup:**
- Proof π: taken from S1 (unchanged)
- Public signals: S1 signals with `outcome` flipped `1 → 0`

**Execution:**
- `Verify(π_S1, tampered_pub) = false`
- Groth16 pairing equations fail because public input commitment no longer matches.

**Result:** `proof generated = true (reused)` | `verified = false` | **✅ PASS**

---

### S7 — Policy Update / Wrong Verification Key

**Scenario:** A governance update replaces the on-chain verification key (e.g., after a circuit revision). A proof generated under the old key is submitted to a verifier using the new key. Simulated by corrupting `IC[0][0]` in the verification key — pairing check fails.

**Setup:**
- Proof π: taken from S1 (unchanged)
- Public signals: from S1 (unchanged)
- Verification key: `IC[0][0]` last 6 digits replaced with `000000`

**Execution:**
- `Verify(π_S1, pub_S1, badVkey) = false`
- Groth16 pairing check fails — proof is not valid under the modified key.

**Result:** `proof generated = true (reused)` | `verified = false` | **✅ PASS**

---

## Constraint Coverage

| Circuit Constraint | Line | Covered by |
|-------------------|------|-----------|
| `credHasher.out === doctorCredentialHash` | 76 | S2 |
| `srcHasher.out === trustedSourceHash` | 87 | S3 |
| `authOk === 0` (action match) | 110 | S1 (positive) |
| `computedOutcome === outcome` | 157 | S4, S5b (negative); S1, S5a (positive) |
| Groth16 binding to public inputs | — | S6 |
| Groth16 binding to verification key | — | S7 |

---

## Security Properties Verified

| Property | Verified by |
|----------|-------------|
| **Completeness** — honest prover always generates valid proof | S1, S5a |
| **Soundness** — no valid proof for false statement | S2, S3, S4, S5b |
| **Zero-knowledge** — proof reveals nothing beyond public inputs | architectural (Groth16 guarantee) |
| **Outcome integrity** — prover cannot misreport the result | S5a + S5b |
| **Replay resistance** — proof bound to exact public input vector | S6 |
| **Key binding** — proof invalidated by verification key change | S7 |
