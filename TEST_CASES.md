# PrescriptionValidation — Test Case Specification

Zero-knowledge proof circuit: `prescription.circom`
Proving system: Groth16 / BN128
Runner: `node prove.js`

---

## Baseline Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| `doctorId` | 123 | Private |
| `doctorSecret` | 456 | Private |
| `doctorCredentialHash` | `Poseidon(123, 456)` | Public — on-chain commitment |
| `sourceId` | 1 | Private (hospital) |
| `trustedSourceHash` | `Poseidon(1)` | Public — on-chain commitment |
| `requiredAction` | 1 | Public — governance policy (prescribe) |
| `deltaMax` | 90 | Public — max data age in days |

---

## Test Cases

---

### S1 — Valid Baseline

**Purpose:** Confirm that a correctly formed proof passes end-to-end.

| Input | Value |
|-------|-------|
| `doctorSecret` | 456 (correct) |
| `sourceId` | 1 (trusted) |
| `dataAge` | 30 days |
| `allergyClassId` | 2 (β-lactam) |
| `medicationClassId` | 5 (antidiabetic) |
| `outcome` | 1 (accept) |

**Circuit path:**
- Check 1: `Poseidon(123, 456) === credHash` ✓
- Check 2: `Poseidon(1) === srcHash` ✓
- Check 3: `30 < 90` → `freshOk = 1` ✓
- Check 4: `1 - 1 = 0` → `authOk` ✓
- Check 5: `5 - 2 ≠ 0` → `noContraindication = 1` ✓
- Final: `computedOutcome = 1 * 1 = 1 === outcome(1)` ✓

**Expected:** `proof generated = true`, `verified = true`

---

### S2 — Invalid Credential

**Purpose:** Verify that a forged or wrong `doctorSecret` cannot produce a valid proof.
The public `doctorCredentialHash` is the correct hash of `(123, 456)`, but the prover
supplies `doctorSecret = 999`. The circuit computes `Poseidon(123, 999)` and asserts it
equals `doctorCredentialHash` — this constraint fails.

| Input | Value |
|-------|-------|
| `doctorSecret` | **999** (forged) |
| `doctorCredentialHash` | `Poseidon(123, 456)` (correct, on-chain) |
| All other inputs | same as S1 |

**Failing constraint:** `credHasher.out === doctorCredentialHash`

**Expected:** `proof generated = false`, `verified = false`

---

### S3 — Untrusted Source

**Purpose:** Verify that a data source not in the governance-approved registry cannot
be used. The prover supplies `sourceId = 99`, but the on-chain `trustedSourceHash` is
`Poseidon(1)`. The circuit computes `Poseidon(99)` — mismatch.

| Input | Value |
|-------|-------|
| `sourceId` | **99** (not trusted) |
| `trustedSourceHash` | `Poseidon(1)` (on-chain, for hospital) |
| All other inputs | same as S1 |

**Failing constraint:** `srcHasher.out === trustedSourceHash`

**Expected:** `proof generated = false`, `verified = false`

---

### S4 — Freshness Violation

**Purpose:** Verify that stale clinical data is rejected. `dataAge = 100` exceeds
`deltaMax = 90`. The `LessThan(32)` gadget returns `freshOk = 0`, so
`computedOutcome = 0 ≠ outcome(1)` — constraint fails.

| Input | Value |
|-------|-------|
| `dataAge` | **100** days |
| `deltaMax` | 90 days |
| `outcome` | 1 (prover claims accept) |
| All other inputs | same as S1 |

**Failing constraint:** `computedOutcome === outcome` (0 ≠ 1)

**Expected:** `proof generated = false`, `verified = false`

---

### S5a — Contraindication Detected, Honest Reject

**Purpose:** Verify that a valid *reject* proof can be generated when a contraindication
exists. `allergyClassId = medicationClassId = 2` → `noContraindication = 0` →
`computedOutcome = 0`. The prover honestly declares `outcome = 0` → constraint `0 === 0`
passes.

| Input | Value |
|-------|-------|
| `allergyClassId` | **2** (β-lactam) |
| `medicationClassId` | **2** (β-lactam — same class) |
| `outcome` | **0** (reject — honest) |
| All other inputs | same as S1 |

**Circuit path:** `isZero = 1` → `noContraindication = 0` → `computedOutcome = 0 === outcome(0)` ✓

**Expected:** `proof generated = true`, `verified = true`

> This demonstrates that a ZKP of *rejection* is also valid and auditable on-chain.

---

### S5b — Outcome Integrity: Approve with Contraindication

**Purpose:** Verify that the prover cannot lie about the outcome when a contraindication
exists. Same contraindication as S5a, but prover claims `outcome = 1` (accept).
`computedOutcome = 0 ≠ 1` — constraint fails.

| Input | Value |
|-------|-------|
| `allergyClassId` | **2** (β-lactam) |
| `medicationClassId` | **2** (β-lactam — same class) |
| `outcome` | **1** (accept — forged) |
| All other inputs | same as S1 |

**Failing constraint:** `computedOutcome === outcome` (0 ≠ 1)

**Expected:** `proof generated = false`, `verified = false`

> Together with S5a, this pair demonstrates full outcome integrity: the prover can only
> publish the outcome that the circuit actually computed.

---

### S6 — Replay / Substitution Attack

**Purpose:** Verify that a valid proof cannot be reused with different public signals.
The S1 proof is taken as-is, but the `outcome` field in the public signals array is
flipped from `1` to `0`. The on-chain verifier must reject this.

**Setup:**
- Proof `π` from S1 (unchanged)
- Public signals from S1, with `outcome` flipped: `1 → 0`

**Why it fails:** Groth16 verification is a pairing check that binds the proof to the
exact public input vector. Any modification to the public signals invalidates the proof.

**Expected:** `proof generated = true` (reused), `verified = false`

> This models an adversary who intercepts a valid proof and attempts to re-submit it with
> a different claimed outcome, or substitute it for a proof in another workflow context.

---

### S7 — Policy Update / Wrong Verification Key

**Purpose:** Verify that a proof generated under one circuit/setup cannot be accepted by
a verifier with a different verification key. This models the scenario where governance
updates the circuit (e.g., after a policy revision) and replaces the on-chain `vk`.

**Setup:**
- Proof `π` and public signals from S1 (unchanged)
- Verification key: corrupted (`IC[0][0]` value modified)

**Why it fails:** The verification key is generated during the trusted setup ceremony and
is bound to the exact circuit. Any mismatch causes the pairing equations to fail.

**Expected:** `proof generated = true` (reused), `verified = false`

> In production, governance would deploy a new `PrescriptionVerifier.sol` with the updated
> `vk` after each circuit revision. Proofs from previous versions are not accepted.

---

## Summary Table

| ID | Scenario | Expect Proof | Expect Verify | Failing Constraint |
|----|----------|:---:|:---:|---|
| S1 | Valid baseline | ✓ | ✓ | — |
| S2 | Invalid credential | ✗ | ✗ | `credHasher.out === doctorCredentialHash` |
| S3 | Untrusted source | ✗ | ✗ | `srcHasher.out === trustedSourceHash` |
| S4 | Freshness violation | ✗ | ✗ | `computedOutcome === outcome` (freshOk=0) |
| S5a | Honest reject (contraindication) | ✓ | ✓ | — |
| S5b | Forged accept (contraindication) | ✗ | ✗ | `computedOutcome === outcome` (0≠1) |
| S6 | Replay / tampered public signals | (reuse) | ✗ | Groth16 pairing check |
| S7 | Wrong verification key | (reuse) | ✗ | Groth16 pairing check |

---

## Running the Tests

```bash
node prove.js
```

Output is color-coded: **green ✓ PASS** / **red ✗ FAIL**.
Results are saved to `test_results.json`.

### Prerequisites

```bash
npm install          # snarkjs, circomlibjs
node ceremony.js     # generates build/ artifacts (if not already present)
```
