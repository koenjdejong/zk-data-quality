use ark_bn254::Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::SynthesisError;

use crate::commitment::FIELDS_PER_RECORD;

pub fn record_fingerprint(
    challenge: &FpVar<Fr>,
    row: &[FpVar<Fr>; FIELDS_PER_RECORD],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut accumulator = row[FIELDS_PER_RECORD - 1].clone();
    for position in (0..FIELDS_PER_RECORD - 1).rev() {
        accumulator = &accumulator * challenge + &row[position];
    }
    Ok(accumulator)
}

pub fn record_stride(challenge: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let mut stride = FpVar::one();
    for _ in 0..FIELDS_PER_RECORD {
        stride *= challenge;
    }
    Ok(stride)
}

pub struct FingerprintFold {
    fingerprint: FpVar<Fr>,
    power_of_stride: FpVar<Fr>,
    record_stride: FpVar<Fr>,
    challenge: FpVar<Fr>,
}

impl FingerprintFold {
    pub fn new(challenge: FpVar<Fr>) -> Result<Self, SynthesisError> {
        Ok(Self {
            fingerprint: FpVar::zero(),
            power_of_stride: FpVar::one(),
            record_stride: record_stride(&challenge)?,
            challenge,
        })
    }

    pub fn absorb_row(&mut self, row: &[FpVar<Fr>; FIELDS_PER_RECORD]) -> Result<(), SynthesisError> {
        let this_record = record_fingerprint(&self.challenge, row)?;
        self.fingerprint += &self.power_of_stride * this_record;
        self.power_of_stride *= &self.record_stride;
        Ok(())
    }

    pub fn finish(self) -> FpVar<Fr> {
        self.fingerprint
    }
}

pub fn fingerprint(rows: &[[Fr; FIELDS_PER_RECORD]], challenge: Fr) -> Fr {
    let mut total = Fr::from(0u64);
    let mut power = Fr::from(1u64);
    for row in rows {
        for field in row {
            total += power * field;
            power *= challenge;
        }
    }
    total
}
