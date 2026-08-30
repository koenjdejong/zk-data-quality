pub mod commitment;
pub mod gp;
pub mod rlc;
pub mod step;

use nova_snark::frontend::test_cs::TestConstraintSystem;
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey};
use nova_snark::provider::GrumpkinEngine;
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use nova_snark::traits::Engine;

use crate::step::{
    MergedStep, SLOT_ACTIVE_COUNT, SLOT_COMMITMENT_CHAIN, SLOT_FINGERPRINT,
    SLOT_GRAND_PRODUCT_ANCHOR, SLOT_GRAND_PRODUCT_KEY1, SLOT_GRAND_PRODUCT_KEY2,
    SLOT_POSITIVE_LOAD_COUNT, SLOT_RECORD_INDEX,
};

#[cfg(not(feature = "hyperkzg"))]
mod selected {
    pub use nova_snark::provider::ipa_pc::EvaluationEngine as PrimaryEvaluationEngine;
    pub use nova_snark::provider::Bn256EngineIPA as PrimaryEngine;
    pub const POLYNOMIAL_COMMITMENT: &str = "ipa";
}

#[cfg(feature = "hyperkzg")]
mod selected {
    pub use nova_snark::provider::hyperkzg::EvaluationEngine as PrimaryEvaluationEngine;
    pub use nova_snark::provider::Bn256EngineKZG as PrimaryEngine;
    pub const POLYNOMIAL_COMMITMENT: &str = "hyperkzg";
}

pub use selected::POLYNOMIAL_COMMITMENT;

pub type Engine1 = selected::PrimaryEngine;

pub type Engine2 = GrumpkinEngine;

pub type EvaluationEngine1 = selected::PrimaryEvaluationEngine<Engine1>;
pub type EvaluationEngine2 = nova_snark::provider::ipa_pc::EvaluationEngine<Engine2>;

pub type Snark1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<Engine1, EvaluationEngine1>;
pub type Snark2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<Engine2, EvaluationEngine2>;

pub type Fr = <Engine1 as Engine>::Scalar;

pub fn field_element_from_decimal(text: &str) -> Result<Fr, String> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{text:?} is not a decimal integer"));
    }
    let ten = Fr::from(10u64);
    let mut accumulator = Fr::from(0u64);
    for digit in text.bytes().map(|byte| u64::from(byte - b'0')) {
        accumulator = accumulator * ten + Fr::from(digit);
    }
    Ok(accumulator)
}

pub fn field_element_from_hex(text: &str) -> Result<Fr, String> {
    use ff::PrimeField;
    let digits = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("{text:?} is not a 0x-prefixed field element"));
    }
    let padded = format!("{digits:0>64}");
    let mut little_endian = [0u8; 32];
    for index in 0..32 {
        little_endian[31 - index] = u8::from_str_radix(&padded[2 * index..2 * index + 2], 16)
            .map_err(|error| format!("{text:?}: {error}"))?;
    }
    let mut representation = Fr::from(0u64).to_repr();
    representation.as_mut().copy_from_slice(&little_endian);
    Option::<Fr>::from(Fr::from_repr(representation))
        .ok_or_else(|| format!("{text:?} is not in the field"))
}

pub fn field_element_to_hex(element: &Fr) -> String {
    use ff::PrimeField;
    let representation = element.to_repr();
    let mut text = String::from("0x");
    for byte in representation.as_ref().iter().rev() {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

pub type Parameters = PublicParams<Engine1, Engine2, MergedStep>;
pub type FoldedProof = RecursiveSNARK<Engine1, Engine2, MergedStep>;
pub type CompressedProof = CompressedSNARK<Engine1, Engine2, MergedStep, Snark1, Snark2>;
pub type CompressedVerifierKey = VerifierKey<Engine1, Engine2, MergedStep, Snark1, Snark2>;

#[derive(Debug)]
pub enum ProvingError {
    Fold { step: usize, reason: String },
    Compress(String),
    Verify(String),
    UnexpectedFinalState { slot: usize, expected: Fr, found: Fr },
}

impl std::fmt::Display for ProvingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fold { step, reason } => write!(formatter, "folding step {step}: {reason}"),
            Self::Compress(reason) => write!(formatter, "compression: {reason}"),
            Self::Verify(reason) => write!(formatter, "verification: {reason}"),
            Self::UnexpectedFinalState { slot, expected, found } => write!(
                formatter,
                "final state slot {slot} is {found:?}, expected {expected:?}"
            ),
        }
    }
}

impl std::error::Error for ProvingError {}

#[derive(Debug)]
pub struct UnsatisfiedStep {
    pub index: usize,
    pub constraint: String,
}

fn synthesize_alone(
    step: &MergedStep,
    initial_state: &[Fr],
) -> (
    TestConstraintSystem<Fr>,
    Result<Vec<AllocatedNum<Fr>>, SynthesisError>,
) {
    let mut constraint_system = TestConstraintSystem::<Fr>::new();
    let state = initial_state
        .iter()
        .enumerate()
        .map(|(slot, value)| {
            AllocatedNum::alloc(
                constraint_system.namespace(|| format!("state_{slot}")),
                || Ok(*value),
            )
            .expect("state allocation")
        })
        .collect::<Vec<_>>();
    let outcome = step.synthesize(&mut constraint_system, &state);
    (constraint_system, outcome)
}

pub fn step_constraint_count(step: &MergedStep, initial_state: &[Fr]) -> usize {
    let (constraint_system, outcome) = synthesize_alone(step, initial_state);
    outcome.expect("step synthesis");
    constraint_system.num_constraints()
}

pub fn simulate(
    steps: &[MergedStep],
    initial_state: &[Fr],
) -> Result<Vec<Fr>, UnsatisfiedStep> {
    let mut state = initial_state.to_vec();
    for (index, step) in steps.iter().enumerate() {
        let (constraint_system, outcome) = synthesize_alone(step, &state);
        let Ok(next) = outcome else {
            return Err(UnsatisfiedStep {
                index,
                constraint: String::from("synthesis failed"),
            });
        };

        if let Some(constraint) = constraint_system.which_is_unsatisfied() {
            return Err(UnsatisfiedStep {
                index,
                constraint: constraint.to_string(),
            });
        }
        state = next
            .iter()
            .map(|value| value.get_value().expect("state value"))
            .collect();
    }
    Ok(state)
}

pub fn setup(sample: &MergedStep) -> Parameters {
    Parameters::setup(sample, &*Snark1::ck_floor(), &*Snark2::ck_floor())
        .expect("public-parameter setup")
}

pub fn fold(
    parameters: &Parameters,
    steps: &[MergedStep],
    initial_state: &[Fr],
) -> Result<FoldedProof, ProvingError> {
    let first = steps.first().expect("at least one step");
    let mut proof = RecursiveSNARK::new(parameters, first, initial_state).map_err(|error| {
        ProvingError::Fold {
            step: 0,
            reason: format!("{error:?}"),
        }
    })?;
    for (index, step) in steps.iter().enumerate() {
        proof
            .prove_step(parameters, step)
            .map_err(|error| ProvingError::Fold {
                step: index,
                reason: format!("{error:?}"),
            })?;
    }
    Ok(proof)
}

pub fn compress(
    parameters: &Parameters,
    proof: &FoldedProof,
) -> Result<(CompressedVerifierKey, CompressedProof), ProvingError> {
    let (proving_key, verifier_key): (
        ProverKey<Engine1, Engine2, MergedStep, Snark1, Snark2>,
        CompressedVerifierKey,
    ) = CompressedSNARK::setup(parameters).map_err(|error| {
        ProvingError::Compress(format!("setup: {error:?}"))
    })?;
    let compressed = CompressedSNARK::prove(parameters, &proving_key, proof)
        .map_err(|error| ProvingError::Compress(format!("prove: {error:?}")))?;
    Ok((verifier_key, compressed))
}

pub fn verify(
    verifier_key: &CompressedVerifierKey,
    compressed: &CompressedProof,
    step_count: usize,
    initial_state: &[Fr],
) -> Result<Vec<Fr>, ProvingError> {
    compressed
        .verify(verifier_key, step_count, initial_state)
        .map_err(|error| ProvingError::Verify(format!("{error:?}")))
}

pub fn check_slot(final_state: &[Fr], slot: usize, expected: Fr) -> Result<(), ProvingError> {
    let found = final_state[slot];
    if found != expected {
        return Err(ProvingError::UnexpectedFinalState { slot, expected, found });
    }
    Ok(())
}

pub struct PublishedClaim {
    pub row_count: usize,
    pub initial_state: Vec<Fr>,
    pub fingerprint_challenge: Fr,
    pub grand_product_challenge: Fr,
    pub commitment: Fr,
    pub fingerprint: Fr,

    pub enabled: dataset::Enabled,
}

pub fn audit(
    verifier_key: &CompressedVerifierKey,
    compressed: &CompressedProof,
    claim: &PublishedClaim,
) -> Result<Vec<Fr>, ProvingError> {
    check_pinned_initial_state(claim)?;

    let final_state = verify(
        verifier_key,
        compressed,
        claim.row_count,
        &claim.initial_state,
    )?;

    check_private_accumulators(&final_state)?;
    check_slot(&final_state, SLOT_RECORD_INDEX, Fr::from(claim.row_count as u64))?;
    if claim.enabled.commitment {
        check_slot(&final_state, SLOT_COMMITMENT_CHAIN, claim.commitment)?;
    }
    if claim.enabled.fingerprint {
        check_slot(&final_state, SLOT_FINGERPRINT, claim.fingerprint)?;
    }
    Ok(final_state)
}

pub fn check_pinned_initial_state(claim: &PublishedClaim) -> Result<(), ProvingError> {
    let expected = crate::step::initial_state(
        claim.fingerprint_challenge,
        crate::rlc::record_stride(claim.fingerprint_challenge),
        claim.grand_product_challenge,
        claim.row_count,
    );
    if claim.initial_state.len() != expected.len() {
        return Err(ProvingError::UnexpectedFinalState {
            slot: expected.len(),
            expected: Fr::from(expected.len() as u64),
            found: Fr::from(claim.initial_state.len() as u64),
        });
    }
    for (slot, value) in expected.iter().enumerate() {
        check_slot(&claim.initial_state, slot, *value)?;
    }
    Ok(())
}

pub const PRIVATE_SLOTS: [usize; 5] = [
    SLOT_ACTIVE_COUNT,
    SLOT_POSITIVE_LOAD_COUNT,
    SLOT_GRAND_PRODUCT_ANCHOR,
    SLOT_GRAND_PRODUCT_KEY1,
    SLOT_GRAND_PRODUCT_KEY2,
];

pub fn check_private_accumulators(final_state: &[Fr]) -> Result<(), ProvingError> {
    for slot in PRIVATE_SLOTS {
        check_slot(final_state, slot, Fr::from(0u64))?;
    }
    Ok(())
}

pub fn public_state_carries_counters(final_state: &[Fr]) -> bool {
    [SLOT_ACTIVE_COUNT, SLOT_POSITIVE_LOAD_COUNT]
        .iter()
        .any(|&slot| final_state[slot] != Fr::from(0u64))
}

pub fn public_state_carries_the_grand_product(final_state: &[Fr]) -> bool {
    [
        SLOT_GRAND_PRODUCT_ANCHOR,
        SLOT_GRAND_PRODUCT_KEY1,
        SLOT_GRAND_PRODUCT_KEY2,
    ]
    .iter()
    .any(|&slot| final_state[slot] != Fr::from(0u64))
}
