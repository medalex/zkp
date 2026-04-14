pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/*
 * PrescriptionValidation Circuit — v2
 *
 * Implements the semantic satisfaction relation (Definition 2, Eq. 13):
 *
 *   M, Γ |= Rx(d, p, m) ⟺
 *       M, Γ |= Au(d, prescribe)    [auth_ok,   Eq. 16]
 *     ∧ M, Γ ⊭ Ct(p, m)            [no_contra, Eq. 17, 21]
 *     ∧ M, Γ |= PolOk(p, m)        [pol_ok,    Eq. 19]
 *
 * Context validity (Definition 1, Eq. 8):
 *   Valid(Γ) ⟺ (t_now − t_s) ≤ Δmax ∧ Auth(cred) ∧ src ∈ S_trusted
 *
 * Statement commitment (Eq. 14):
 *   stmtHash = H(φ+ ‖ policyVersion ‖ nonce)
 *            = Poseidon(doctorId, doctorSecret, patientId, medicationId,
 *                       sourceId, policyVersion, nonce)
 *
 * Composition (Eq. 20–23):
 *   valid_ctx   = fresh_ok  ∧ auth_ok      (Eq. 20)
 *   no_contra   = ¬allergy_contra          (Eq. 21)
 *   clinical_ok = no_contra ∧ pol_ok       (Eq. 22)
 *   outcome     = valid_ctx ∧ clinical_ok  (Eq. 23)
 *
 * Public inputs  (7): stmtHash, outcome, tsAnchor, nonce, deltaMax, theta, requiredAction
 * Private inputs (11): doctorId, doctorSecret, patientId, medicationId, sourceId,
 *                      policyVersion, dataAge, authorizedAction,
 *                      allergyClassId, medicationClassId, clinVal
 */
template PrescriptionValidation() {

    // =========================================================================
    // PRIVATE INPUTS — witness w = ⟨w_id, w_ctx, w_clin, w_ont, w_aux⟩  (Eq. 24)
    // =========================================================================

    // w_id: identity components committed into stmtHash
    signal input doctorId;          // prescriber identifier
    signal input doctorSecret;      // prescriber private key / password
    signal input patientId;         // patient identifier
    signal input medicationId;      // medication identifier (e.g., 5 = Metformin)
    signal input sourceId;          // data source identifier (e.g., 1 = hospital)
    signal input policyVersion;     // governance-approved theory snapshot version

    // w_ctx: context validity  [Definition 1]
    signal input dataAge;           // t_now − t_s in days
    signal input authorizedAction;  // action code performed: prescribe = 1  [Eq. 16]

    // w_clin: clinical evidence  [Eq. 17, 19]
    signal input allergyClassId;    // patient's allergen drug class (e.g., 2 = β-lactam)
    signal input medicationClassId; // prescribed drug class          (e.g., 5 = antidiabetic)
    signal input clinVal;           // patient's measured eGFR value  [Pol(m, eGFR, ≥, θ)]


    // =========================================================================
    // PUBLIC INPUTS — pub = ⟨stmtHash, outcome, tsAnchor, nonce, deltaMax, theta, requiredAction⟩
    // (Eq. 25)
    // =========================================================================

    signal input stmtHash;       // H(φ+ ‖ policyVersion ‖ nonce)           [Eq. 14]
    signal input outcome;        // 1 = accept, 0 = reject
    signal input tsAnchor;       // coarse-grained time anchor for auditability (no circuit constraint)
    signal input nonce;          // per-workflow unique value (replay protection)
    signal input deltaMax;       // Δmax: maximum permitted data age in days  [Def. 1]
    signal input theta;          // θ: clinical policy threshold, e.g., eGFR ≥ 30  [Eq. 19]
    signal input requiredAction; // governance policy action code: prescribe = 1


    // =========================================================================
    // SUB-CIRCUIT 1: Statement binding — stmtHash  [Eq. 14]
    //
    // Verifies: Poseidon(doctorId, doctorSecret, patientId, medicationId,
    //                    sourceId, policyVersion, nonce) = stmtHash
    //
    // This single constraint simultaneously enforces Auth(cred) and src ∈ S_trusted:
    // any wrong identity component produces a hash mismatch and fails the proof.
    // =========================================================================
    component hasher = Poseidon(7);
    hasher.inputs[0] <== doctorId;
    hasher.inputs[1] <== doctorSecret;
    hasher.inputs[2] <== patientId;
    hasher.inputs[3] <== medicationId;
    hasher.inputs[4] <== sourceId;
    hasher.inputs[5] <== policyVersion;
    hasher.inputs[6] <== nonce;

    hasher.out === stmtHash;


    // =========================================================================
    // SUB-CIRCUIT 2: auth_ok — Au(d, prescribe)  [Eq. 16]
    //
    // The prescriber's action must match the governance-required action.
    // Identity binding (Auth(cred), src ∈ S_trusted) is enforced by stmtHash above.
    // =========================================================================
    component authComp = IsEqual();
    authComp.in[0] <== authorizedAction;
    authComp.in[1] <== requiredAction;
    signal authOk;
    authOk <== authComp.out;  // 1 if authorized, 0 otherwise


    // =========================================================================
    // SUB-CIRCUIT 3: fresh_ok — (t_now − t_s) ≤ Δmax  [Eq. 18, Definition 1]
    //
    // Clinical evidence must not be stale. Uses ≤ per paper Definition 1 (Eq. 8).
    // =========================================================================
    component freshComp = LessEqThan(32);
    freshComp.in[0] <== dataAge;
    freshComp.in[1] <== deltaMax;
    signal freshOk;
    freshOk <== freshComp.out;  // 1 if fresh, 0 if stale


    // =========================================================================
    // SUB-CIRCUIT 4: no_contra — ¬Ct(p, m)  [Eq. 17, 21]
    //
    // Contraindication is present when allergyClassId == medicationClassId
    // (patient is allergic to the same drug class as the prescribed medication).
    // Implemented using the is-zero gadget pattern.
    // =========================================================================
    signal classDiff;
    classDiff <== allergyClassId - medicationClassId;

    signal classDiffInv;
    classDiffInv <-- (classDiff == 0) ? 0 : (1 / classDiff);

    signal allergyContra;
    allergyContra <== 1 - (classDiff * classDiffInv);  // 1 if contraindicated
    classDiff * allergyContra === 0;                    // is-zero correctness constraint

    signal noContra;
    noContra <== 1 - allergyContra;  // 1 if safe to prescribe, 0 if contraindicated


    // =========================================================================
    // SUB-CIRCUIT 5: pol_ok — PolOk(p, m)  [Eq. 19]
    //
    // Enforces clinical policy axiom Pol(Metformin, eGFR, ≥, θ):
    //   pol_ok = 1  ⟺  clinVal ≥ theta
    // Patient's eGFR must meet the governance-approved threshold (θ = 30 per FDA).
    // The clinical value clinVal remains private; only theta is public.
    // =========================================================================
    component polComp = GreaterEqThan(32);
    polComp.in[0] <== clinVal;
    polComp.in[1] <== theta;
    signal polOk;
    polOk <== polComp.out;  // 1 if eGFR ≥ θ, 0 if renal impairment


    // =========================================================================
    // FINAL COMPOSITION — Eq. 20–23
    //
    //   valid_ctx   = fresh_ok  * auth_ok      (Eq. 20)  — AND via multiplication
    //   no_contra   = 1 - allergyContra        (Eq. 21)  — NOT via subtraction
    //   clinical_ok = no_contra * pol_ok        (Eq. 22)  — AND via multiplication
    //   outcome     = valid_ctx * clinical_ok   (Eq. 23)  — AND via multiplication
    //
    // Boolean signals b ∈ {0,1} enforced by b*(b-1)=0 inside circomlib components.
    // A single failure in any sub-circuit sets outcome = 0.
    // =========================================================================
    signal validCtx;
    validCtx <== freshOk * authOk;

    signal clinicalOk;
    clinicalOk <== noContra * polOk;

    signal computedOutcome;
    computedOutcome <== validCtx * clinicalOk;

    // The declared public outcome must match what the circuit computed.
    // This prevents the prover from lying about the result.
    computedOutcome === outcome;

    // tsAnchor is committed as a public input for on-chain auditability.
    // The governance layer records the time anchor; no additional circuit constraint needed.
    // (Public inputs are automatically included in the Groth16 IC accumulator.)
}

/*
 * Public inputs declared here are visible to the on-chain verifier (Eq. 25):
 *   pub = ⟨stmtHash, outcome, tsAnchor, nonce, deltaMax, theta, requiredAction⟩
 * 7 public inputs — matches Table VII and Table VIII of the paper.
 */
component main {public [
    stmtHash,
    outcome,
    tsAnchor,
    nonce,
    deltaMax,
    theta,
    requiredAction
]} = PrescriptionValidation();
