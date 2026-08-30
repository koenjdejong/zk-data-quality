use std::str::FromStr;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, One, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use dataset::{Constants, Enabled, Row};

use crate::commitment::{CommitmentOpening, FIELDS_PER_RECORD};
use crate::gp::GrandProduct;
use crate::rlc::FingerprintFold;

#[derive(Clone, Debug)]
pub struct PreparedRow {
    pub record_id: Fr,
    pub active: bool,
    pub vehicle_id: u64,
    pub start: u64,
    pub end: u64,
    pub origin_hub: u64,
    pub destination_hub: u64,
    pub load_kg: u64,
}

impl PreparedRow {
    pub fn from_row(row: &Row) -> Result<Self, String> {
        Ok(Self {
            record_id: Fr::from_str(&row.record_id)
                .map_err(|_| format!("record_id {:?} is not a field element", row.record_id))?,
            active: row.active,
            vehicle_id: row.vehicle_id,
            start: row.start,
            end: row.end,
            origin_hub: row.origin_hub,
            destination_hub: row.destination_hub,
            load_kg: row.load_kg,
        })
    }

    pub fn prepare_all(rows: &[Row]) -> Result<Vec<Self>, String> {
        rows.iter().map(Self::from_row).collect()
    }

    pub fn field_elements(&self) -> [Fr; FIELDS_PER_RECORD] {
        [
            self.record_id,
            Fr::from(u64::from(self.active)),
            Fr::from(self.vehicle_id),
            Fr::from(self.start),
            Fr::from(self.end),
            Fr::from(self.origin_hub),
            Fr::from(self.destination_hub),
            Fr::from(self.load_kg),
        ]
    }
}

pub fn commitment_of(traversals: &[Vec<PreparedRow>]) -> Fr {
    let lanes: Vec<Vec<[Fr; FIELDS_PER_RECORD]>> = traversals
        .iter()
        .map(|rows| rows.iter().map(PreparedRow::field_elements).collect())
        .collect();
    crate::commitment::commitment(&lanes)
}

pub fn grand_product_of(
    rows: &[PreparedRow],
    fingerprint_challenge: Fr,
    grand_product_challenge: Fr,
    blinding_element: Fr,
) -> Fr {
    crate::gp::grand_product(
        &rows.iter().map(PreparedRow::field_elements).collect::<Vec<_>>(),
        fingerprint_challenge,
        grand_product_challenge,
        blinding_element,
    )
}

pub fn fingerprint_of(rows: &[PreparedRow], challenge: Fr) -> Fr {
    crate::rlc::fingerprint(
        &rows.iter().map(PreparedRow::field_elements).collect::<Vec<_>>(),
        challenge,
    )
}

pub struct RowVariables {
    record_id: FpVar<Fr>,
    active: Boolean<Fr>,
    vehicle_id: FpVar<Fr>,
    start: FpVar<Fr>,
    end: FpVar<Fr>,
    origin_hub: FpVar<Fr>,
    destination_hub: FpVar<Fr>,
    load_kg: FpVar<Fr>,
}

impl RowVariables {
    fn allocate(
        constraint_system: ConstraintSystemRef<Fr>,
        row: &PreparedRow,
        constants: &Constants,
    ) -> Result<Self, SynthesisError> {
        let witness = |value: Fr| {
            FpVar::new_witness(constraint_system.clone(), || Ok(value))
        };
        let start = witness(Fr::from(row.start))?;
        let end = witness(Fr::from(row.end))?;
        enforce_range(&start, constants.range_check_bits.start)?;
        enforce_range(&end, constants.range_check_bits.end)?;

        Ok(Self {
            record_id: witness(row.record_id)?,
            active: Boolean::new_witness(constraint_system.clone(), || Ok(row.active))?,
            vehicle_id: witness(Fr::from(row.vehicle_id))?,
            start,
            end,
            origin_hub: witness(Fr::from(row.origin_hub))?,
            destination_hub: witness(Fr::from(row.destination_hub))?,
            load_kg: witness(Fr::from(row.load_kg))?,
        })
    }

    fn field_elements(&self) -> [FpVar<Fr>; FIELDS_PER_RECORD] {
        [
            self.record_id.clone(),
            FpVar::from(self.active.clone()),
            self.vehicle_id.clone(),
            self.start.clone(),
            self.end.clone(),
            self.origin_hub.clone(),
            self.destination_hub.clone(),
            self.load_kg.clone(),
        ]
    }
}

fn enforce_identifiers_present(row: &RowVariables) -> Result<(), SynthesisError> {
    for identifier in [&row.record_id, &row.vehicle_id] {
        enforce_nonzero(&row.active.select(identifier, &FpVar::one())?)?;
    }
    Ok(())
}

fn enforce_time_window(row: &RowVariables, constants: &Constants) -> Result<(), SynthesisError> {
    let bits = constants.range_check_bits.start;
    let lower_bound = FpVar::constant(Fr::from(constants.time_minimum));
    let upper_bound = FpVar::constant(Fr::from(constants.time_maximum));

    enforce_less_or_equal(
        &lower_bound,
        &row.active.select(&row.start, &lower_bound)?,
        bits,
    )?;
    enforce_less_or_equal(
        &row.active.select(&row.end, &FpVar::zero())?,
        &upper_bound,
        bits,
    )?;
    enforce_less(
        &row.active.select(&row.start, &FpVar::zero())?,
        &row.active.select(&row.end, &FpVar::one())?,
        bits,
    )
}

struct LoadRatio {
    active_count: FpVar<Fr>,
    positive_load_count: FpVar<Fr>,
}

impl LoadRatio {
    fn new() -> Self {
        Self {
            active_count: FpVar::zero(),
            positive_load_count: FpVar::zero(),
        }
    }

    fn absorb_row(&mut self, row: &RowVariables) -> Result<(), SynthesisError> {
        let carries_load = row.load_kg.is_neq(&FpVar::zero())?;
        let counts = &row.active & &carries_load;
        self.active_count += FpVar::from(row.active.clone());
        self.positive_load_count += FpVar::from(counts);
        Ok(())
    }

    fn enforce(self, constants: &Constants) -> Result<(), SynthesisError> {
        let required =
            self.active_count * FpVar::constant(Fr::from(constants.positive_load_ratio_numerator));
        let achieved = self.positive_load_count
            * FpVar::constant(Fr::from(constants.positive_load_ratio_denominator));
        enforce_less_or_equal(&required, &achieved, constants.count_bits)
    }
}

fn enforce_hubs_whitelisted(
    row: &RowVariables,
    constants: &Constants,
) -> Result<(), SynthesisError> {
    let whitelisted = FpVar::constant(Fr::from(constants.allowed_hubs[0]));
    for hub in [&row.origin_hub, &row.destination_hub] {
        enforce_member_of(
            &row.active.select(hub, &whitelisted)?,
            &constants.allowed_hubs,
        )?;
    }
    Ok(())
}

#[derive(Clone)]
pub struct DataQualityCircuit {
    pub rows: Vec<PreparedRow>,
    pub constants: Constants,

    pub published_commitment: Fr,

    pub fingerprint_challenge: Fr,

    pub expected_fingerprint: Fr,

    pub sorted_by_vehicle_and_start: Vec<PreparedRow>,

    pub sorted_by_record_id: Vec<PreparedRow>,

    pub grand_product_challenge: Fr,

    pub grand_product_blinding_element: Fr,

    pub all_pairs: bool,

    pub enabled: Enabled,
}

impl ConstraintSynthesizer<Fr> for DataQualityCircuit {
    fn generate_constraints(
        self,
        constraint_system: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {

        let published_commitment =
            FpVar::new_input(constraint_system.clone(), || Ok(self.published_commitment))?;
        let fingerprint_challenge =
            FpVar::new_input(constraint_system.clone(), || Ok(self.fingerprint_challenge))?;
        let expected_fingerprint =
            FpVar::new_input(constraint_system.clone(), || Ok(self.expected_fingerprint))?;
        let grand_product_challenge =
            FpVar::new_input(constraint_system.clone(), || Ok(self.grand_product_challenge))?;

        let blinding_element = FpVar::new_witness(constraint_system.clone(), || {
            Ok(self.grand_product_blinding_element)
        })?;

        let enabled = self.enabled;

        let takes_a_product = self.all_pairs || enabled.any_grand_product();

        let mut opening =
            enabled.commitment.then(|| CommitmentOpening::new(constraint_system.clone()));
        let mut fold = enabled
            .fingerprint
            .then(|| FingerprintFold::new(fingerprint_challenge.clone()))
            .transpose()?;
        let mut load_ratio = LoadRatio::new();
        let mut anchor_grand_product = if takes_a_product {
            Some(GrandProduct::seeded_with_pad(
                blinding_element.clone(),
                fingerprint_challenge.clone(),
                grand_product_challenge.clone(),
            )?)
        } else {
            None
        };

        let allocate_view = |rows: &[PreparedRow]| {
            rows.iter()
                .map(|row| RowVariables::allocate(constraint_system.clone(), row, &self.constants))
                .collect::<Result<Vec<_>, SynthesisError>>()
        };

        let mut view_lanes: Vec<Option<Vec<RowVariables>>> = Vec::new();
        if !self.all_pairs {

            view_lanes.push(
                enabled
                    .sigma1()
                    .then(|| allocate_view(&self.sorted_by_vehicle_and_start))
                    .transpose()?,
            );
            view_lanes.push(
                enabled
                    .sigma2()
                    .then(|| allocate_view(&self.sorted_by_record_id))
                    .transpose()?,
            );
        }
        let absent_lane: [FpVar<Fr>; FIELDS_PER_RECORD] = std::array::from_fn(|_| FpVar::zero());

        let mut anchor_rows = Vec::with_capacity(self.rows.len());
        for (index, row) in self.rows.iter().enumerate() {

            let variables =
                RowVariables::allocate(constraint_system.clone(), row, &self.constants)?;
            if enabled.p1 {
                enforce_identifiers_present(&variables)?;
            }
            if enabled.p2 {
                enforce_time_window(&variables, &self.constants)?;
            }
            if enabled.p3 {
                enforce_hubs_whitelisted(&variables, &self.constants)?;
            }

            if enabled.p4 {
                load_ratio.absorb_row(&variables)?;
            }

            let field_elements = variables.field_elements();

            if let Some(opening) = opening.as_mut() {
                let mut tuple = Vec::with_capacity(1 + view_lanes.len());
                tuple.push(field_elements.clone());
                for lane in &view_lanes {
                    tuple.push(match lane {
                        Some(view) => view[index].field_elements(),
                        None => absent_lane.clone(),
                    });
                }
                opening.absorb_step(&tuple)?;
            }

            if let Some(fold) = fold.as_mut() {
                fold.absorb_row(&field_elements)?;
            }
            if let Some(product) = anchor_grand_product.as_mut() {
                product.absorb_row(&field_elements)?;
            }
            anchor_rows.push(variables);
        }
        let anchor_grand_product = anchor_grand_product.map(GrandProduct::finish);

        if let Some(opening) = opening {
            opening.finish()?.enforce_equal(&published_commitment)?;
        }
        if let Some(fold) = fold {
            fold.finish().enforce_equal(&expected_fingerprint)?;
        }
        if enabled.p4 {
            load_ratio.enforce(&self.constants)?;
        }

        if self.all_pairs {

            return enforce_no_same_vehicle_overlap_all_pairs(&anchor_rows, &self.constants);
        }

        let mut lanes = view_lanes.into_iter();
        let by_vehicle_and_start = lanes.next().flatten();
        let by_record_id = lanes.next().flatten();

        let link_to_anchor = |view: &[RowVariables]| -> Result<(), SynthesisError> {
            let Some(anchor_grand_product) = anchor_grand_product.as_ref() else {
                return Ok(());
            };
            let mut product = GrandProduct::seeded_with_pad(
                blinding_element.clone(),
                fingerprint_challenge.clone(),
                grand_product_challenge.clone(),
            )?;
            for row in view {
                product.absorb_row(&row.field_elements())?;
            }
            product.finish().enforce_equal(anchor_grand_product)
        };

        if let Some(by_vehicle_and_start) = by_vehicle_and_start {
            if enabled.order1 {
                enforce_sorted(
                    &by_vehicle_and_start,
                    SortKey::VehicleAndStart,
                    true,
                    &self.constants,
                )?;
                if enabled.p5 {
                    enforce_no_same_vehicle_overlap(&by_vehicle_and_start, &self.constants)?;
                }
            }
            if enabled.product1 {
                link_to_anchor(&by_vehicle_and_start)?;
            }
        }

        if let Some(by_record_id) = by_record_id {
            if enabled.order2 {
                enforce_sorted(
                    &by_record_id,
                    SortKey::RecordIdentifier,
                    enabled.p6,
                    &self.constants,
                )?;
            }
            if enabled.product2 {
                link_to_anchor(&by_record_id)?;
            }
        }
        Ok(())
    }
}

pub fn enforce_range(value: &FpVar<Fr>, bits: usize) -> Result<(), SynthesisError> {
    let constraint_system = value.cs();
    let little_endian_bits: Option<Vec<bool>> =
        value.value().ok().map(|element| element.into_bigint().to_bits_le());

    let mut recomposed = FpVar::<Fr>::zero();
    let mut coefficient = Fr::one();
    for position in 0..bits {
        let bit_value = little_endian_bits.as_ref().map(|bits| bits[position]);
        let bit = Boolean::new_witness(constraint_system.clone(), || {
            bit_value.ok_or(SynthesisError::AssignmentMissing)
        })?;
        recomposed += FpVar::from(bit) * FpVar::constant(coefficient);
        coefficient.double_in_place();
    }
    recomposed.enforce_equal(value)
}

pub fn enforce_less_or_equal(
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
    bits: usize,
) -> Result<(), SynthesisError> {
    enforce_range(&(right - left), bits)
}

pub fn enforce_less(
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
    bits: usize,
) -> Result<(), SynthesisError> {
    enforce_range(&(right - left - FpVar::one()), bits)
}

pub fn enforce_nonzero(value: &FpVar<Fr>) -> Result<(), SynthesisError> {
    value.enforce_not_equal(&FpVar::zero())
}

pub fn enforce_member_of(
    value: &FpVar<Fr>,
    members: &[u64],
) -> Result<(), SynthesisError> {
    assert!(!members.is_empty(), "the whitelist must not be empty");
    let mut product = FpVar::<Fr>::one();
    for &member in members {
        product *= value - FpVar::constant(Fr::from(member));
    }
    product.enforce_equal(&FpVar::zero())
}

pub fn is_less_or_equal(
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
    bits: usize,
) -> Result<Boolean<Fr>, SynthesisError> {
    let constraint_system = left.cs().or(right.cs());
    let mut offset = Fr::one();
    for _ in 0..bits {
        offset.double_in_place();
    }
    let shifted = right - left + FpVar::constant(offset);

    let little_endian: Option<Vec<bool>> =
        shifted.value().ok().map(|element| element.into_bigint().to_bits_le());
    let mut recomposed = FpVar::<Fr>::zero();
    let mut coefficient = Fr::one();
    let mut top = Boolean::FALSE;
    for position in 0..=bits {
        let bit_value = little_endian.as_ref().map(|bits| bits[position]);
        let bit = Boolean::new_witness(constraint_system.clone(), || {
            bit_value.ok_or(SynthesisError::AssignmentMissing)
        })?;
        recomposed += FpVar::from(bit.clone()) * FpVar::constant(coefficient);
        coefficient.double_in_place();
        if position == bits {
            top = bit;
        }
    }
    recomposed.enforce_equal(&shifted)?;
    Ok(top)
}

#[derive(Clone, Copy, Debug)]
pub enum SortKey {

    VehicleAndStart,

    RecordIdentifier,
}

impl SortKey {


    fn strict(self) -> bool {
        matches!(self, Self::RecordIdentifier)
    }

    fn bits(self, constants: &Constants) -> usize {
        match self {
            Self::VehicleAndStart => {
                constants.range_check_bits.vehicle_id + constants.range_check_bits.start
            }
            Self::RecordIdentifier => constants.range_check_bits.record_id,
        }
    }

    fn packed(
        self,
        row: &RowVariables,
        gate: &Boolean<Fr>,
        constants: &Constants,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        match self {
            Self::VehicleAndStart => {
                let vehicle_id = gate.select(&row.vehicle_id, &FpVar::zero())?;
                let start = gate.select(&row.start, &FpVar::zero())?;
                enforce_range(&vehicle_id, constants.range_check_bits.vehicle_id)?;
                enforce_range(&start, constants.range_check_bits.start)?;
                let shift = FpVar::constant(shift_of(constants.range_check_bits.start));
                Ok(vehicle_id * shift + start)
            }
            Self::RecordIdentifier => {
                let record_id = gate.select(&row.record_id, &FpVar::zero())?;
                enforce_range(&record_id, constants.range_check_bits.record_id)?;
                Ok(record_id)
            }
        }
    }
}

fn shift_of(bits: usize) -> Fr {
    let mut shift = Fr::ONE;
    for _ in 0..bits {
        shift.double_in_place();
    }
    shift
}

pub fn enforce_sorted(
    view: &[RowVariables],
    key: SortKey,
    strict: bool,
    constants: &Constants,
) -> Result<(), SynthesisError> {

    let keys = view
        .iter()
        .map(|row| key.packed(row, &row.active, constants))
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    for (position, window) in view.windows(2).enumerate() {
        let (previous, current) = (&window[0], &window[1]);

        let resurrected = &current.active & &!&previous.active;
        resurrected.enforce_equal(&Boolean::FALSE)?;

        let both_active = &previous.active & &current.active;
        let previous_key = both_active.select(&keys[position], &FpVar::zero())?;
        if strict && key.strict() {

            let ceiling = both_active.select(&keys[position + 1], &FpVar::one())?;
            enforce_less(&previous_key, &ceiling, key.bits(constants))?;
        } else {
            let current_key = both_active.select(&keys[position + 1], &FpVar::zero())?;
            enforce_less_or_equal(&previous_key, &current_key, key.bits(constants))?;
        }
    }
    Ok(())
}

pub fn enforce_no_same_vehicle_overlap(
    view: &[RowVariables],
    constants: &Constants,
) -> Result<(), SynthesisError> {
    for window in view.windows(2) {
        let (previous, current) = (&window[0], &window[1]);
        let same_vehicle = previous.vehicle_id.is_eq(&current.vehicle_id)?;
        let applies = (&previous.active & &current.active) & &same_vehicle;
        let previous_end = applies.select(&previous.end, &FpVar::zero())?;
        let start = applies.select(&current.start, &FpVar::zero())?;
        enforce_less_or_equal(&previous_end, &start, constants.range_check_bits.start)?;
    }
    Ok(())
}

pub fn enforce_no_same_vehicle_overlap_all_pairs(
    rows: &[RowVariables],
    constants: &Constants,
) -> Result<(), SynthesisError> {
    let bits = constants.range_check_bits.start;
    for (position, first) in rows.iter().enumerate() {
        for second in &rows[position + 1..] {
            let same_vehicle = first.vehicle_id.is_eq(&second.vehicle_id)?;
            let applies = (&first.active & &second.active) & &same_vehicle;
            let first_then_second = is_less_or_equal(&first.end, &second.start, bits)?;
            let second_then_first = is_less_or_equal(&second.end, &first.start, bits)?;
            let disjoint = first_then_second | second_then_first;
            (applies & &!disjoint).enforce_equal(&Boolean::FALSE)?;
        }
    }
    Ok(())
}
