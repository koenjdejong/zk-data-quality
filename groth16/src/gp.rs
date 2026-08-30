use ark_bn254::Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::SynthesisError;

use crate::commitment::FIELDS_PER_RECORD;
use crate::rlc::record_fingerprint;

pub struct GrandProduct {
    product: FpVar<Fr>,
    fingerprint_challenge: FpVar<Fr>,
    grand_product_challenge: FpVar<Fr>,
}

impl GrandProduct {

    pub fn seeded_with_pad(
        blinding_element: FpVar<Fr>,
        fingerprint_challenge: FpVar<Fr>,
        grand_product_challenge: FpVar<Fr>,
    ) -> Result<Self, SynthesisError> {

        blinding_element.enforce_not_equal(&FpVar::zero())?;
        Ok(Self {
            product: blinding_element,
            fingerprint_challenge,
            grand_product_challenge,
        })
    }

    pub fn absorb_row(&mut self, row: &[FpVar<Fr>; FIELDS_PER_RECORD]) -> Result<(), SynthesisError> {
        let record = record_fingerprint(&self.fingerprint_challenge, row)?;
        self.product *= &self.grand_product_challenge - record;
        Ok(())
    }

    pub fn finish(self) -> FpVar<Fr> {
        self.product
    }
}

pub fn grand_product(
    rows: &[[Fr; FIELDS_PER_RECORD]],
    fingerprint_challenge: Fr,
    grand_product_challenge: Fr,
    blinding_element: Fr,
) -> Fr {
    let mut product = blinding_element;
    for row in rows {
        let mut record = Fr::from(0u64);
        let mut power = Fr::from(1u64);
        for field in row {
            record += power * field;
            power *= fingerprint_challenge;
        }
        product *= grand_product_challenge - record;
    }
    product
}
