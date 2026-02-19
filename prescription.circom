pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/*
 * PrescriptionValidation Circuit
 * 
 * Implements the semantic satisfaction relation from Definition 5 (formula 12):
 * M, I |= Rx(d, p, m) <=> Valid(I) AND Au(I, prescribe) AND NOT Ct(p, m)
 * 
 * Where Valid(I) is defined in Definition 4 (formula 11):
 * Valid(I) <=> (t_now - t_s) < Δmax AND Auth(cred) AND src ∈ S_trusted
 *
 * All patient-specific data stays in the private witness (off-chain).
 * Only commitments and the binary outcome are revealed on-chain.
 */
template PrescriptionValidation() {

    // ========================================
    // PRIVATE INPUTS (witness) — not revealed
    // ========================================

    // Doctor identity — used for Auth(cred) check, Definition 4 formula (11)
    signal input doctorId;
    signal input doctorSecret;        // private key/password known only to doctor

    // Action being performed — used for Au(I, prescribe) check, formula (12)
    signal input authorizedAction;    // encoded action: prescribe = 1

    // Data source identity — used for src ∈ S_trusted check, formula (11)
    signal input sourceId;            // e.g. hospital = 1, lab = 2

    // Data age in days — used for (t_now - t_s) < Δmax check, formula (11)
    signal input dataAge;             // t_now - t_s

    // Clinical evidence — used for NOT Ct(p, m) check, formula (12)
    signal input allergyClassId;      // drug class of patient's allergen (e.g. beta-lactam = 2)
    signal input medicationClassId;   // drug class of prescribed medication (e.g. Metformin = 5)


    // ========================================
    // PUBLIC INPUTS — visible on-chain
    // ========================================

    // Commitment to doctor credentials: H(doctorId, doctorSecret)
    // Stored in governance registry on-chain
    signal input doctorCredentialHash;

    // Commitment to trusted data source: H(sourceId)
    // Governance-approved source list anchored on-chain
    signal input trustedSourceHash;

    // Required action code for prescription workflow
    // Governance policy parameter: prescribe = 1
    signal input requiredAction;

    // Maximum allowed data age in days (governance parameter)
    // e.g. deltaMax = 90 days per FDA/ADA guidelines
    signal input deltaMax;

    // Expected outcome: 1 = accept, 0 = reject
    // Verified against computed outcome at the end
    signal input outcome;


    // ========================================
    // CHECK 1: Auth(cred) — Definition 4, formula (11)
    // Verify doctor credentials using Poseidon hash
    // Prover knows (doctorId, doctorSecret) but only hash is public
    // ========================================
    component credHasher = Poseidon(2);
    credHasher.inputs[0] <== doctorId;
    credHasher.inputs[1] <== doctorSecret;

    // Computed hash must match the on-chain credential hash
    credHasher.out === doctorCredentialHash;


    // ========================================
    // CHECK 2: src ∈ S_trusted — Definition 4, formula (11)
    // Verify that data source is in the governance-approved trusted set
    // ========================================
    component srcHasher = Poseidon(1);
    srcHasher.inputs[0] <== sourceId;

    // Computed source hash must match the on-chain trusted source hash
    srcHasher.out === trustedSourceHash;


    // ========================================
    // CHECK 3: (t_now - t_s) < Δmax — Definition 4, formula (11)
    // Verify that clinical data is fresh enough
    // ========================================
    component freshCheck = LessThan(32);  // 32-bit comparison
    freshCheck.in[0] <== dataAge;
    freshCheck.in[1] <== deltaMax;

    signal freshOk;
    freshOk <== freshCheck.out;           // 1 if dataAge < deltaMax, else 0


    // ========================================
    // CHECK 4: Au(I, prescribe) — Definition 5, formula (12)
    // Verify that interpreter is authorized to perform prescribe action
    // ========================================
    signal authOk;
    authOk <== authorizedAction - requiredAction;

    // Difference must be 0 — actions must match exactly
    authOk === 0;


    // ========================================
    // CHECK 5: NOT Ct(p, m) — Definition 5, formula (12)
    // Verify no contraindication exists between allergy class and medication class
    // Contraindication occurs when allergyClassId == medicationClassId
    // e.g. patient allergic to Penicillin (beta-lactam class = 2)
    //      prescribed Amoxicillin (beta-lactam class = 2) => contraindication!
    //      prescribed Metformin (antidiabetic class = 5)  => no contraindication
    // ========================================
    signal classDiff;
    classDiff <== allergyClassId - medicationClassId;

    // is_zero pattern: isZero = 1 if classDiff == 0 (contraindication exists)
    signal classDiffInv;
    classDiffInv <-- (classDiff == 0) ? 0 : (1 / classDiff);

    signal isZero;
    isZero <== 1 - (classDiff * classDiffInv);

    // Enforce correctness of is_zero pattern
    classDiff * isZero === 0;

    // noContraindication = 1 if classes differ (safe to prescribe)
    signal noContraindication;
    noContraindication <== 1 - isZero;


    // ========================================
    // FINAL COMPOSITION — formulas (48-51)
    // valid_ctx   = freshOk AND credOk AND srcTrusted  (checks 1, 2, 3)
    // auth_ok     = Au(I, prescribe)                   (check 4)
    // clinical_ok = NOT Ct(p, m)                       (check 5)
    // outcome     = valid_ctx AND auth_ok AND clinical_ok
    //
    // Note: credOk and srcTrusted are enforced via === constraints above
    // so validCtx here carries only freshOk as a signal
    // ========================================
    signal validCtx;
    validCtx <== freshOk;

    signal computedOutcome;
    computedOutcome <== validCtx * noContraindication;

    // Final check: computed outcome must match the declared public outcome
    // This prevents the prover from lying about the result
    computedOutcome === outcome;
}

/*
 * Public inputs declared here are visible to the on-chain verifier.
 * All other signals remain private (zero-knowledge property).
 * Corresponds to pub = <stmt_hash, outcome, timestamp> from formula (53)
 */
component main {public [
    doctorCredentialHash,   // H(doctorId, doctorSecret) — Auth(cred)
    trustedSourceHash,      // H(sourceId) — src ∈ S_trusted
    requiredAction,         // Au(I, prescribe)
    deltaMax,               // Δmax — freshness bound
    outcome                 // accept/reject result
]} = PrescriptionValidation();