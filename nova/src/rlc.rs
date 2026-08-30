use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};

use crate::commitment::FIELDS_PER_RECORD;
use crate::Fr;

pub fn record_fingerprint<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    challenge: &AllocatedNum<Fr>,
    row: &[AllocatedNum<Fr>; FIELDS_PER_RECORD],
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let mut accumulator = row[FIELDS_PER_RECORD - 1].clone();
    for position in (0..FIELDS_PER_RECORD - 1).rev() {
        let field = &row[position];
        let next = AllocatedNum::alloc(
            constraint_system.namespace(|| format!("horner_{position}")),
            || {
                let accumulator = accumulator
                    .get_value()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                let challenge = challenge.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let field = field.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                Ok(accumulator * challenge + field)
            },
        )?;

        constraint_system.enforce(
            || format!("horner_constraint_{position}"),
            |lc| lc + accumulator.get_variable(),
            |lc| lc + challenge.get_variable(),
            |lc| lc + next.get_variable() - field.get_variable(),
        );
        accumulator = next;
    }
    Ok(accumulator)
}

pub fn fold_record<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    fingerprint: &AllocatedNum<Fr>,
    power_of_stride: &AllocatedNum<Fr>,
    record_fingerprint: &AllocatedNum<Fr>,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let next = AllocatedNum::alloc(constraint_system.namespace(|| "fingerprint"), || {
        let fingerprint = fingerprint.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let power = power_of_stride
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let record = record_fingerprint
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(fingerprint + power * record)
    })?;

    constraint_system.enforce(
        || "fingerprint_fold",
        |lc| lc + power_of_stride.get_variable(),
        |lc| lc + record_fingerprint.get_variable(),
        |lc| lc + next.get_variable() - fingerprint.get_variable(),
    );
    Ok(next)
}

pub fn record_stride(challenge: Fr) -> Fr {
    let mut stride = Fr::from(1u64);
    for _ in 0..FIELDS_PER_RECORD {
        stride *= challenge;
    }
    stride
}
