use generic_array::typenum::U25;
use nova_snark::frontend::gadgets::poseidon::{
    Elt, IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp,
    SpongeTrait, Strength,
};
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};

use crate::Fr;

pub const FIELDS_PER_RECORD: usize = 8;

pub fn initial_chain() -> Fr {
    Fr::from(0u64)
}

pub const TRAVERSAL_COUNT: usize = 3;

pub const ABSORB_TUPLE_LENGTH: u32 = (TRAVERSAL_COUNT * FIELDS_PER_RECORD) as u32 + 1;

pub type TupleArity = U25;
pub type TupleConstants = PoseidonConstants<Fr, TupleArity>;

pub fn tuple_constants() -> TupleConstants {
    Sponge::<Fr, TupleArity>::api_constants(Strength::Standard)
}

fn absorb_tuple_then_squeeze() -> IOPattern {
    IOPattern(vec![
        SpongeOp::Absorb(ABSORB_TUPLE_LENGTH),
        SpongeOp::Squeeze(1),
    ])
}

fn tuple_elements(chain: Fr, tuple: &[[Fr; FIELDS_PER_RECORD]]) -> Vec<Fr> {
    let mut elements = Vec::with_capacity(ABSORB_TUPLE_LENGTH as usize);
    elements.push(chain);
    for lane in tuple {
        elements.extend_from_slice(lane);
    }
    elements
}

pub fn absorb_tuple(
    constants: &TupleConstants,
    chain: Fr,
    tuple: &[[Fr; FIELDS_PER_RECORD]],
) -> Fr {
    assert_eq!(
        tuple.len(),
        TRAVERSAL_COUNT,
        "the commitment absorbs one row of every traversal"
    );
    let mut sponge = Sponge::<Fr, TupleArity>::new_with_constants(constants, Simplex);
    let accumulator = &mut ();
    sponge.start(absorb_tuple_then_squeeze(), None, accumulator);

    let elements = tuple_elements(chain, tuple);
    SpongeAPI::absorb(&mut sponge, ABSORB_TUPLE_LENGTH, &elements, accumulator);

    let output = SpongeAPI::squeeze(&mut sponge, 1, accumulator);
    sponge.finish(accumulator).expect("sponge io pattern");
    output[0]
}

pub fn tuple_commitment(traversals: &[Vec<[Fr; FIELDS_PER_RECORD]>]) -> Fr {
    let constants = tuple_constants();
    let row_count = traversals.first().map_or(0, Vec::len);
    (0..row_count).fold(initial_chain(), |chain, index| {
        let tuple: Vec<[Fr; FIELDS_PER_RECORD]> =
            traversals.iter().map(|lane| lane[index]).collect();
        absorb_tuple(&constants, chain, &tuple)
    })
}

pub fn absorb_tuple_in_circuit<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    constants: &TupleConstants,
    chain: &AllocatedNum<Fr>,
    tuple: &[[AllocatedNum<Fr>; FIELDS_PER_RECORD]],
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    assert_eq!(
        tuple.len(),
        TRAVERSAL_COUNT,
        "the commitment absorbs one row of every traversal"
    );
    let elements: Vec<Elt<Fr>> = std::iter::once(chain)
        .chain(tuple.iter().flatten())
        .map(|element| Elt::Allocated(element.clone()))
        .collect();

    let output = {
        let mut namespace = constraint_system.namespace(|| "commitment_chain");
        let mut sponge = SpongeCircuit::<Fr, TupleArity, _>::new_with_constants(constants, Simplex);
        sponge.start(absorb_tuple_then_squeeze(), None, &mut namespace);
        SpongeAPI::absorb(&mut sponge, ABSORB_TUPLE_LENGTH, &elements, &mut namespace);
        let output = SpongeAPI::squeeze(&mut sponge, 1, &mut namespace);
        sponge.finish(&mut namespace).expect("sponge io pattern");
        output
    };

    Elt::ensure_allocated(
        &output[0],
        &mut constraint_system.namespace(|| "allocate_commitment_chain"),
    )
}
