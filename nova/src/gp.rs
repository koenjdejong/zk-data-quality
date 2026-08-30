use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};

use crate::Fr;

pub fn fold_grand_product<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    grand_product: &AllocatedNum<Fr>,
    challenge: &AllocatedNum<Fr>,
    record_fingerprint: &AllocatedNum<Fr>,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let next = AllocatedNum::alloc(constraint_system.namespace(|| "grand_product"), || {
        let product = grand_product
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let challenge = challenge.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let record = record_fingerprint
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(product * (challenge - record))
    })?;

    constraint_system.enforce(
        || "grand_product_fold",
        |lc| lc + grand_product.get_variable(),
        |lc| lc + challenge.get_variable() - record_fingerprint.get_variable(),
        |lc| lc + next.get_variable(),
    );
    Ok(next)
}

