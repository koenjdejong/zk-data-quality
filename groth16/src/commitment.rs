use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

pub const FIELDS_PER_RECORD: usize = 8;

const RATE: usize = FIELDS_PER_RECORD;
const CAPACITY: usize = 1;

const ALPHA: u64 = 5;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const SKIP_MATRICES: u64 = 0;

pub fn configuration() -> PoseidonConfig<Fr> {
    let (round_constants, mixing_matrix) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        SKIP_MATRICES,
    );
    PoseidonConfig::new(
        FULL_ROUNDS,
        PARTIAL_ROUNDS,
        ALPHA,
        mixing_matrix,
        round_constants,
        RATE,
        CAPACITY,
    )
}

pub fn commitment(traversals: &[Vec<[Fr; FIELDS_PER_RECORD]>]) -> Fr {
    let mut sponge = PoseidonSponge::new(&configuration());
    for index in 0..traversals.first().map_or(0, Vec::len) {
        for traversal in traversals {
            sponge.absorb(&traversal[index].as_slice());
        }
    }
    sponge.squeeze_native_field_elements(1)[0]
}

pub struct CommitmentOpening {
    sponge: PoseidonSpongeVar<Fr>,
}

impl CommitmentOpening {
    pub fn new(constraint_system: ConstraintSystemRef<Fr>) -> Self {
        Self {
            sponge: PoseidonSpongeVar::new(constraint_system, &configuration()),
        }
    }

    pub fn absorb_step(
        &mut self,
        tuple: &[[FpVar<Fr>; FIELDS_PER_RECORD]],
    ) -> Result<(), SynthesisError> {
        for lane in tuple {
            self.sponge.absorb(&lane.as_slice())?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.sponge.squeeze_field_elements(1)?.remove(0))
    }
}
