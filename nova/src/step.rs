use std::sync::Arc;

use ff::{Field, PrimeField};
use nova_snark::frontend::{
    num::AllocatedNum, AllocatedBit, Boolean, ConstraintSystem, SynthesisError,
};
use nova_snark::gadgets::utils::{
    alloc_constant, alloc_num_equals, conditionally_select, le_bits_to_num,
};
use nova_snark::traits::circuit::StepCircuit;

use crate::commitment::{absorb_tuple_in_circuit, initial_chain, TupleConstants, FIELDS_PER_RECORD};
use crate::{field_element_from_decimal, Fr};
use crate::gp::fold_grand_product;
use crate::rlc::{fold_record, record_fingerprint};

fn bit_of(value: &Fr, position: usize) -> bool {
    let representation = value.to_repr();
    (representation.as_ref()[position / 8] >> (position % 8)) & 1 == 1
}

pub fn enforce_range<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    value: &AllocatedNum<Fr>,
    bits: usize,
) -> Result<(), SynthesisError> {
    let allocated_bits = (0..bits)
        .map(|position| {
            AllocatedBit::alloc(
                constraint_system.namespace(|| format!("bit_{position}")),
                value.get_value().map(|element| bit_of(&element, position)),
            )
        })
        .collect::<Result<Vec<AllocatedBit>, SynthesisError>>()?;
    let recomposed = le_bits_to_num(
        constraint_system.namespace(|| "recompose"),
        &allocated_bits,
    )?;
    constraint_system.enforce(
        || "recomposed == value",
        |lc| lc + recomposed.get_variable() - value.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(())
}

fn allocate_difference<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    left: &AllocatedNum<Fr>,
    right: &AllocatedNum<Fr>,
    offset: Fr,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let difference = AllocatedNum::alloc(constraint_system.namespace(|| "difference"), || {
        let left = left.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let right = right.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(right - left - offset)
    })?;
    constraint_system.enforce(
        || "difference == right - left - offset",
        |lc| {
            lc + difference.get_variable() + left.get_variable() - right.get_variable()
                + (offset, CS::one())
        },
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(difference)
}

pub fn enforce_less_or_equal<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    left: &AllocatedNum<Fr>,
    right: &AllocatedNum<Fr>,
    bits: usize,
) -> Result<(), SynthesisError> {
    let difference = allocate_difference(
        constraint_system.namespace(|| "left <= right"),
        left,
        right,
        Fr::ZERO,
    )?;
    enforce_range(constraint_system.namespace(|| "range"), &difference, bits)
}

pub fn enforce_less<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    left: &AllocatedNum<Fr>,
    right: &AllocatedNum<Fr>,
    bits: usize,
) -> Result<(), SynthesisError> {
    let difference = allocate_difference(
        constraint_system.namespace(|| "left < right"),
        left,
        right,
        Fr::ONE,
    )?;
    enforce_range(constraint_system.namespace(|| "range"), &difference, bits)
}

pub fn enforce_nonzero<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    value: &AllocatedNum<Fr>,
) -> Result<(), SynthesisError> {
    let inverse = AllocatedNum::alloc(constraint_system.namespace(|| "inverse"), || {
        let value = value.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Option::<Fr>::from(value.invert()).ok_or(SynthesisError::DivisionByZero)
    })?;
    constraint_system.enforce(
        || "value * inverse == 1",
        |lc| lc + value.get_variable(),
        |lc| lc + inverse.get_variable(),
        |lc| lc + CS::one(),
    );
    Ok(())
}

pub fn enforce_member_of<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    value: &AllocatedNum<Fr>,
    members: &[u64],
) -> Result<(), SynthesisError> {
    assert!(!members.is_empty(), "the whitelist must not be empty");

    let difference = |constraint_system: &mut CS, index: usize, member: u64| {
        let member = Fr::from(member);
        let difference = AllocatedNum::alloc(
            constraint_system.namespace(|| format!("difference_{index}")),
            || {
                let value = value.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                Ok(value - member)
            },
        )?;
        constraint_system.enforce(
            || format!("difference_{index} == value - member"),
            |lc| lc + difference.get_variable() - value.get_variable() + (member, CS::one()),
            |lc| lc + CS::one(),
            |lc| lc,
        );
        Ok::<AllocatedNum<Fr>, SynthesisError>(difference)
    };

    let mut product = difference(&mut constraint_system, 0, members[0])?;
    for (index, &member) in members.iter().enumerate().skip(1) {
        let factor = difference(&mut constraint_system, index, member)?;
        product = product.mul(
            constraint_system.namespace(|| format!("product_{index}")),
            &factor,
        )?;
    }
    constraint_system.enforce(
        || "product == 0",
        |lc| lc + product.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(())
}

pub fn select<CS: ConstraintSystem<Fr>>(
    constraint_system: CS,
    condition: &Boolean,
    left: &AllocatedNum<Fr>,
    right: &AllocatedNum<Fr>,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    conditionally_select(constraint_system, left, right, condition)
}

pub fn select_or_constant<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    condition: &Boolean,
    value: &AllocatedNum<Fr>,
    constant: Fr,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let allocated = alloc_constant(constraint_system.namespace(|| "constant"), &constant)?;
    select(
        constraint_system.namespace(|| "select"),
        condition,
        value,
        &allocated,
    )
}

pub fn boolean_to_number<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    boolean: &Boolean,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let number = AllocatedNum::alloc(constraint_system.namespace(|| "number"), || {
        boolean
            .get_value()
            .map(|bit| if bit { Fr::ONE } else { Fr::ZERO })
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    constraint_system.enforce(
        || "number == boolean",
        |_| boolean.lc(CS::one(), Fr::ONE),
        |lc| lc + CS::one(),
        |lc| lc + number.get_variable(),
    );
    Ok(number)
}

pub fn enforce_increment<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    previous: &AllocatedNum<Fr>,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let next = AllocatedNum::alloc(constraint_system.namespace(|| "next"), || {
        let previous = previous.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(previous + Fr::ONE)
    })?;
    constraint_system.enforce(
        || "next == previous + 1",
        |lc| lc + next.get_variable() - previous.get_variable() - CS::one(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(next)
}

pub fn is_equal<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    left: &AllocatedNum<Fr>,
    right: &AllocatedNum<Fr>,
) -> Result<Boolean, SynthesisError> {
    Ok(Boolean::from(alloc_num_equals(
        constraint_system.namespace(|| "equals"),
        left,
        right,
    )?))
}

pub fn is_nonzero<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    value: &AllocatedNum<Fr>,
) -> Result<Boolean, SynthesisError> {
    let zero = alloc_constant(constraint_system.namespace(|| "zero"), &Fr::ZERO)?;
    Ok(is_equal(constraint_system.namespace(|| "is_zero"), value, &zero)?.not())
}

pub fn scale_by_constant<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    value: &AllocatedNum<Fr>,
    factor: Fr,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let scaled = AllocatedNum::alloc(constraint_system.namespace(|| "scaled"), || {
        let value = value.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(value * factor)
    })?;
    constraint_system.enforce(
        || "scaled == value * factor",
        |lc| lc + scaled.get_variable() - (factor, value.get_variable()),
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(scaled)
}

pub fn number_to_boolean<CS: ConstraintSystem<Fr>>(
    mut constraint_system: CS,
    value: &AllocatedNum<Fr>,
) -> Result<Boolean, SynthesisError> {
    let bit = AllocatedBit::alloc(
        constraint_system.namespace(|| "bit"),
        value.get_value().map(|element| element != Fr::ZERO),
    )?;
    constraint_system.enforce(
        || "bit == value",
        |lc| lc + bit.get_variable() - value.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(Boolean::from(bit))
}

#[derive(Clone)]
pub struct StepConstants {
    pub time_minimum: u64,
    pub time_maximum: u64,
    pub allowed_hubs: Vec<u64>,
    pub time_bits: usize,
    pub count_bits: usize,
    pub positive_load_ratio_numerator: u64,
    pub positive_load_ratio_denominator: u64,
}

impl StepConstants {
    pub fn from_dataset(constants: &dataset::Constants) -> Self {
        assert_eq!(
            constants.range_check_bits.start, constants.range_check_bits.end,
            "start and end are compared against each other, so they share one width"
        );
        Self {
            time_minimum: constants.time_minimum,
            time_maximum: constants.time_maximum,
            allowed_hubs: constants.allowed_hubs.clone(),
            time_bits: constants.range_check_bits.start,
            count_bits: constants.count_bits,
            positive_load_ratio_numerator: constants.positive_load_ratio_numerator,
            positive_load_ratio_denominator: constants.positive_load_ratio_denominator,
        }
    }
}

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
    pub fn from_row(row: &dataset::Row) -> Result<Self, String> {
        Ok(Self {
            record_id: field_element_from_decimal(&row.record_id)?,
            active: row.active,
            vehicle_id: row.vehicle_id,
            start: row.start,
            end: row.end,
            origin_hub: row.origin_hub,
            destination_hub: row.destination_hub,
            load_kg: row.load_kg,
        })
    }

    pub fn prepare_all(rows: &[dataset::Row]) -> Result<Vec<Self>, String> {
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

pub struct RowVariables {
    pub record_id: AllocatedNum<Fr>,
    pub active: Boolean,
    pub active_as_number: AllocatedNum<Fr>,
    pub vehicle_id: AllocatedNum<Fr>,
    pub start: AllocatedNum<Fr>,
    pub end: AllocatedNum<Fr>,
    pub origin_hub: AllocatedNum<Fr>,
    pub destination_hub: AllocatedNum<Fr>,
    pub load_kg: AllocatedNum<Fr>,
}

impl RowVariables {
    pub fn allocate<CS: ConstraintSystem<Fr>>(
        constraint_system: &mut CS,
        row: &PreparedRow,
        constants: &StepConstants,
    ) -> Result<Self, SynthesisError> {
        let record_id = AllocatedNum::alloc(constraint_system.namespace(|| "record_id"), || {
            Ok(row.record_id)
        })?;
        let vehicle_id = AllocatedNum::alloc(constraint_system.namespace(|| "vehicle_id"), || {
            Ok(Fr::from(row.vehicle_id))
        })?;
        let start =
            AllocatedNum::alloc(constraint_system.namespace(|| "start"), || Ok(Fr::from(row.start)))?;
        let end =
            AllocatedNum::alloc(constraint_system.namespace(|| "end"), || Ok(Fr::from(row.end)))?;
        let origin_hub = AllocatedNum::alloc(constraint_system.namespace(|| "origin_hub"), || {
            Ok(Fr::from(row.origin_hub))
        })?;
        let destination_hub =
            AllocatedNum::alloc(constraint_system.namespace(|| "destination_hub"), || {
                Ok(Fr::from(row.destination_hub))
            })?;
        let load_kg = AllocatedNum::alloc(constraint_system.namespace(|| "load_kg"), || {
            Ok(Fr::from(row.load_kg))
        })?;

        let active = Boolean::from(AllocatedBit::alloc(
            constraint_system.namespace(|| "active"),
            Some(row.active),
        )?);
        let active_as_number = boolean_to_number(
            constraint_system.namespace(|| "active_as_number"),
            &active,
        )?;

        enforce_range(
            constraint_system.namespace(|| "start_range"),
            &start,
            constants.time_bits,
        )?;
        enforce_range(
            constraint_system.namespace(|| "end_range"),
            &end,
            constants.time_bits,
        )?;

        Ok(Self {
            record_id,
            active,
            active_as_number,
            vehicle_id,
            start,
            end,
            origin_hub,
            destination_hub,
            load_kg,
        })
    }

    pub fn field_elements(&self) -> [AllocatedNum<Fr>; FIELDS_PER_RECORD] {
        [
            self.record_id.clone(),
            self.active_as_number.clone(),
            self.vehicle_id.clone(),
            self.start.clone(),
            self.end.clone(),
            self.origin_hub.clone(),
            self.destination_hub.clone(),
            self.load_kg.clone(),
        ]
    }
}

pub fn enforce_identifiers_present<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    row: &RowVariables,
) -> Result<(), SynthesisError> {
    for (name, identifier) in [("record_id", &row.record_id), ("vehicle_id", &row.vehicle_id)] {
        let gated = select_or_constant(
            constraint_system.namespace(|| format!("{name}_gated")),
            &row.active,
            identifier,
            Fr::ONE,
        )?;
        enforce_nonzero(
            constraint_system.namespace(|| format!("{name}_nonzero")),
            &gated,
        )?;
    }
    Ok(())
}

pub fn enforce_time_window<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    row: &RowVariables,
    constants: &StepConstants,
) -> Result<(), SynthesisError> {
    let time_minimum = Fr::from(constants.time_minimum);
    let time_maximum = Fr::from(constants.time_maximum);
    let bits = constants.time_bits;

    let lower_bound =
        alloc_constant(constraint_system.namespace(|| "time_minimum"), &time_minimum)?;
    let upper_bound =
        alloc_constant(constraint_system.namespace(|| "time_maximum"), &time_maximum)?;

    let start_or_bound = select_or_constant(
        constraint_system.namespace(|| "start_or_bound"),
        &row.active,
        &row.start,
        time_minimum,
    )?;
    enforce_less_or_equal(
        constraint_system.namespace(|| "time_minimum <= start"),
        &lower_bound,
        &start_or_bound,
        bits,
    )?;

    let end_or_zero = select_or_constant(
        constraint_system.namespace(|| "end_or_zero"),
        &row.active,
        &row.end,
        Fr::ZERO,
    )?;
    enforce_less_or_equal(
        constraint_system.namespace(|| "end <= time_maximum"),
        &end_or_zero,
        &upper_bound,
        bits,
    )?;

    let start_or_zero = select_or_constant(
        constraint_system.namespace(|| "start_or_zero"),
        &row.active,
        &row.start,
        Fr::ZERO,
    )?;
    let end_or_one = select_or_constant(
        constraint_system.namespace(|| "end_or_one"),
        &row.active,
        &row.end,
        Fr::ONE,
    )?;
    enforce_less(
        constraint_system.namespace(|| "start < end"),
        &start_or_zero,
        &end_or_one,
        bits,
    )
}

pub fn enforce_hubs_whitelisted<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    row: &RowVariables,
    constants: &StepConstants,
) -> Result<(), SynthesisError> {
    let whitelisted = Fr::from(constants.allowed_hubs[0]);
    for (name, hub) in [
        ("origin_hub", &row.origin_hub),
        ("destination_hub", &row.destination_hub),
    ] {
        let gated = select_or_constant(
            constraint_system.namespace(|| format!("{name}_gated")),
            &row.active,
            hub,
            whitelisted,
        )?;
        enforce_member_of(
            constraint_system.namespace(|| format!("{name}_whitelisted")),
            &gated,
            &constants.allowed_hubs,
        )?;
    }
    Ok(())
}

pub fn accumulate_and_assert_load_ratio<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    row: &RowVariables,
    active_count: &AllocatedNum<Fr>,
    positive_load_count: &AllocatedNum<Fr>,
    is_final_row: &Boolean,
    zero: &AllocatedNum<Fr>,
    constants: &StepConstants,
) -> Result<(AllocatedNum<Fr>, AllocatedNum<Fr>), SynthesisError> {
    let carries_load = is_nonzero(
        constraint_system.namespace(|| "load_kg != 0"),
        &row.load_kg,
    )?;
    let counts_towards_ratio = Boolean::and(
        constraint_system.namespace(|| "active and carries load"),
        &row.active,
        &carries_load,
    )?;
    let counts_as_number = boolean_to_number(
        constraint_system.namespace(|| "counts_as_number"),
        &counts_towards_ratio,
    )?;

    let accumulated_active = active_count.add(
        constraint_system.namespace(|| "accumulate_active"),
        &row.active_as_number,
    )?;
    let accumulated_positive = positive_load_count.add(
        constraint_system.namespace(|| "accumulate_positive_load"),
        &counts_as_number,
    )?;

    let required = scale_by_constant(
        constraint_system.namespace(|| "required"),
        &accumulated_active,
        Fr::from(constants.positive_load_ratio_numerator),
    )?;
    let achieved = scale_by_constant(
        constraint_system.namespace(|| "achieved"),
        &accumulated_positive,
        Fr::from(constants.positive_load_ratio_denominator),
    )?;
    let gated_required = select(
        constraint_system.namespace(|| "gated_required"),
        is_final_row,
        &required,
        zero,
    )?;
    let gated_achieved = select(
        constraint_system.namespace(|| "gated_achieved"),
        is_final_row,
        &achieved,
        zero,
    )?;
    enforce_less_or_equal(
        constraint_system.namespace(|| "positive_load_ratio"),
        &gated_required,
        &gated_achieved,
        constants.count_bits,
    )?;

    let published_active = select(
        constraint_system.namespace(|| "publish_active_count"),
        is_final_row,
        zero,
        &accumulated_active,
    )?;
    let published_positive = select(
        constraint_system.namespace(|| "publish_positive_load_count"),
        is_final_row,
        zero,
        &accumulated_positive,
    )?;
    Ok((published_active, published_positive))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {

    VehicleAndStart,

    RecordIdentifier,
}

impl SortKey {

    pub fn predicate(self) -> &'static str {
        match self {
            Self::VehicleAndStart => "no_same_vehicle_overlap",
            Self::RecordIdentifier => "record_ids_strictly_increasing",
        }
    }

    pub fn strict(self) -> bool {
        matches!(self, Self::RecordIdentifier)
    }

}

#[derive(Clone, Debug)]
pub struct SortConstants {
    pub key: SortKey,
    pub vehicle_id_bits: usize,
    pub time_bits: usize,
    pub record_id_bits: usize,
}

impl SortConstants {
    pub fn from_dataset(constants: &dataset::Constants, key: SortKey) -> Self {
        Self {
            key,
            vehicle_id_bits: constants.range_check_bits.vehicle_id,
            time_bits: constants.range_check_bits.start,
            record_id_bits: constants.range_check_bits.record_id,
        }
    }

    pub fn packed_key_bits(&self) -> usize {
        match self.key {
            SortKey::VehicleAndStart => self.vehicle_id_bits + self.time_bits,
            SortKey::RecordIdentifier => self.record_id_bits,
        }
    }
}

pub fn power_of_two(exponent: usize) -> Fr {
    let mut value = Fr::ONE;
    for _ in 0..exponent {
        value = value.double();
    }
    value
}

pub const FIELD_RECORD_ID: usize = 0;
pub const FIELD_ACTIVE: usize = 1;
pub const FIELD_VEHICLE_ID: usize = 2;
pub const FIELD_START: usize = 3;
pub const FIELD_END: usize = 4;

pub struct GatedFields {
    pub packed_key: AllocatedNum<Fr>,
    pub vehicle_id: AllocatedNum<Fr>,
    pub start: AllocatedNum<Fr>,
    pub end: AllocatedNum<Fr>,

    pub raw: [AllocatedNum<Fr>; crate::commitment::FIELDS_PER_RECORD],
}

impl GatedFields {

    pub fn allocate<CS: ConstraintSystem<Fr>>(
        constraint_system: &mut CS,
        raw: [AllocatedNum<Fr>; crate::commitment::FIELDS_PER_RECORD],
        constants: &SortConstants,
        active: &Boolean,
        needs_end: bool,
    ) -> Result<Self, SynthesisError> {
        let mut gated = |name: &'static str, value: &AllocatedNum<Fr>, bits: usize| {
            let gated = select_or_constant(
                constraint_system.namespace(|| format!("{name}_gated")),
                active,
                value,
                Fr::ZERO,
            )?;
            enforce_range(
                constraint_system.namespace(|| format!("{name}_range")),
                &gated,
                bits,
            )?;
            Ok::<AllocatedNum<Fr>, SynthesisError>(gated)
        };

        let key = constants.key;
        match key {
            SortKey::VehicleAndStart => {
                let vehicle_id = gated(
                    "vehicle_id",
                    &raw[FIELD_VEHICLE_ID],
                    constants.vehicle_id_bits,
                )?;
                let start = gated("start", &raw[FIELD_START], constants.time_bits)?;
                let end = if needs_end {
                    gated("end", &raw[FIELD_END], constants.time_bits)?
                } else {
                    AllocatedNum::alloc(constraint_system.namespace(|| "unused_end"), || {
                        Ok(Fr::ZERO)
                    })?
                };

                let shift = power_of_two(constants.time_bits);
                let packed_key =
                    AllocatedNum::alloc(constraint_system.namespace(|| "packed_key"), || {
                        let vehicle_id = vehicle_id
                            .get_value()
                            .ok_or(SynthesisError::AssignmentMissing)?;
                        let start = start.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                        Ok(vehicle_id * shift + start)
                    })?;
                constraint_system.enforce(
                    || "packed_key == vehicle_id shifted by time_bits, plus start",
                    |lc| {
                        lc + packed_key.get_variable()
                            - (shift, vehicle_id.get_variable())
                            - start.get_variable()
                    },
                    |lc| lc + CS::one(),
                    |lc| lc,
                );
                Ok(Self {
                    packed_key,
                    vehicle_id,
                    start,
                    end,
                    raw,
                })
            }
            SortKey::RecordIdentifier => {
                let record_id = gated(
                    "record_id",
                    &raw[FIELD_RECORD_ID],
                    constants.record_id_bits,
                )?;
                let unused = AllocatedNum::alloc(
                    constraint_system.namespace(|| "unused"),
                    || Ok(Fr::ZERO),
                )?;
                Ok(Self {
                    packed_key: record_id,
                    vehicle_id: unused.clone(),
                    start: unused.clone(),
                    end: unused,
                    raw,
                })
            }
        }
    }
}

pub fn allocate_raw_row<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    row: &PreparedRow,
) -> Result<[AllocatedNum<Fr>; crate::commitment::FIELDS_PER_RECORD], SynthesisError> {
    let values = row.field_elements();
    let mut allocated = Vec::with_capacity(values.len());
    for (position, value) in values.into_iter().enumerate() {
        allocated.push(AllocatedNum::alloc(
            constraint_system.namespace(|| format!("raw_{position}")),
            || Ok(value),
        )?);
    }
    Ok(allocated.try_into().expect("eight fields"))
}

pub fn enforce_no_same_vehicle_overlap<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    previous_vehicle_id: &AllocatedNum<Fr>,
    previous_end: &AllocatedNum<Fr>,
    fields: &GatedFields,
    both_active: &Boolean,
    constants: &SortConstants,
) -> Result<(), SynthesisError> {
    let same_vehicle = is_equal(
        constraint_system.namespace(|| "same_vehicle"),
        previous_vehicle_id,
        &fields.vehicle_id,
    )?;
    let applies = Boolean::and(
        constraint_system.namespace(|| "same vehicle and both active"),
        both_active,
        &same_vehicle,
    )?;
    let previous_end = select_or_constant(
        constraint_system.namespace(|| "gated_previous_end"),
        &applies,
        previous_end,
        Fr::ZERO,
    )?;
    let start = select_or_constant(
        constraint_system.namespace(|| "gated_start"),
        &applies,
        &fields.start,
        Fr::ZERO,
    )?;
    enforce_less_or_equal(
        constraint_system.namespace(|| "no_same_vehicle_overlap"),
        &previous_end,
        &start,
        constants.time_bits,
    )
}

pub const STATE_LENGTH: usize = 19;

pub const SLOT_RECORD_INDEX: usize = 0;
pub const SLOT_COMMITMENT_CHAIN: usize = 1;
pub const SLOT_FINGERPRINT: usize = 2;
pub const SLOT_POWER_OF_STRIDE: usize = 3;
pub const SLOT_FINGERPRINT_CHALLENGE: usize = 4;
pub const SLOT_RECORD_STRIDE: usize = 5;
pub const SLOT_RECORD_COUNT_TOTAL: usize = 6;
pub const SLOT_ACTIVE_COUNT: usize = 7;
pub const SLOT_POSITIVE_LOAD_COUNT: usize = 8;
pub const SLOT_GRAND_PRODUCT_CHALLENGE: usize = 9;

pub const SLOT_GRAND_PRODUCT_ANCHOR: usize = 10;
pub const SLOT_GRAND_PRODUCT_KEY1: usize = 11;
pub const SLOT_GRAND_PRODUCT_KEY2: usize = 12;
pub const SLOT_KEY1_PREVIOUS_ACTIVE: usize = 13;
pub const SLOT_KEY1_PREVIOUS_PACKED_KEY: usize = 14;
pub const SLOT_KEY1_PREVIOUS_VEHICLE_ID: usize = 15;
pub const SLOT_KEY1_PREVIOUS_END: usize = 16;
pub const SLOT_KEY2_PREVIOUS_ACTIVE: usize = 17;
pub const SLOT_KEY2_PREVIOUS_PACKED_KEY: usize = 18;

#[derive(Clone)]
pub struct MergedConstants {
    pub anchor: StepConstants,
    pub key1: SortConstants,
    pub key2: SortConstants,

    pub tuple_constants: Arc<TupleConstants>,
}

impl MergedConstants {
    pub fn from_dataset(constants: &dataset::Constants) -> Self {
        Self {
            anchor: StepConstants::from_dataset(constants),
            key1: SortConstants::from_dataset(constants, SortKey::VehicleAndStart),
            key2: SortConstants::from_dataset(constants, SortKey::RecordIdentifier),
            tuple_constants: Arc::new(crate::commitment::tuple_constants()),
        }
    }
}

#[derive(Clone)]
pub struct MergedStep {
    pub anchor: PreparedRow,
    pub key1: PreparedRow,
    pub key2: PreparedRow,

    pub pad: Fr,
    pub constants: MergedConstants,

    pub enabled: dataset::Enabled,
}

#[derive(Clone, Copy)]
struct LaneAblation {

    enforce_ordering: bool,

    strict_key_comparison: bool,

    assert_no_same_vehicle_overlap: bool,
}

struct LaneWires {
    raw: [AllocatedNum<Fr>; FIELDS_PER_RECORD],
    gated: Option<GatedFields>,
}

struct ViewSlots {
    previous_active: usize,
    previous_packed_key: usize,
    previous_vehicle_id: Option<usize>,
    previous_end: Option<usize>,
}

const KEY1_SLOTS: ViewSlots = ViewSlots {
    previous_active: SLOT_KEY1_PREVIOUS_ACTIVE,
    previous_packed_key: SLOT_KEY1_PREVIOUS_PACKED_KEY,
    previous_vehicle_id: Some(SLOT_KEY1_PREVIOUS_VEHICLE_ID),
    previous_end: Some(SLOT_KEY1_PREVIOUS_END),
};

const KEY2_SLOTS: ViewSlots = ViewSlots {
    previous_active: SLOT_KEY2_PREVIOUS_ACTIVE,
    previous_packed_key: SLOT_KEY2_PREVIOUS_PACKED_KEY,
    previous_vehicle_id: None,
    previous_end: None,
};

fn enforce_view<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    row: &PreparedRow,
    state: &[AllocatedNum<Fr>],
    slots: &ViewSlots,
    constants: &SortConstants,
    lane: LaneAblation,
) -> Result<LaneWires, SynthesisError> {

    let raw = allocate_raw_row(constraint_system, row)?;

    if !lane.enforce_ordering {
        return Ok(LaneWires { raw, gated: None });
    }
    let active = number_to_boolean(
        constraint_system.namespace(|| "active"),
        &raw[FIELD_ACTIVE],
    )?;

    let previous_active = number_to_boolean(
        constraint_system.namespace(|| "previous_active"),
        &state[slots.previous_active],
    )?;

    let resurrected = Boolean::and(
        constraint_system.namespace(|| "active_after_padding"),
        &active,
        &previous_active.not(),
    )?;
    Boolean::enforce_equal(
        constraint_system.namespace(|| "active rows form a prefix"),
        &resurrected,
        &Boolean::constant(false),
    )?;

    let fields = GatedFields::allocate(
        constraint_system,
        raw,
        constants,
        &active,
        lane.assert_no_same_vehicle_overlap,
    )?;

    let both_active = Boolean::and(
        constraint_system.namespace(|| "both_active"),
        &previous_active,
        &active,
    )?;
    let previous_key = select_or_constant(
        constraint_system.namespace(|| "gated_previous_key"),
        &both_active,
        &state[slots.previous_packed_key],
        Fr::ZERO,
    )?;
    let current_key = select_or_constant(
        constraint_system.namespace(|| "gated_current_key"),
        &both_active,
        &fields.packed_key,
        Fr::ZERO,
    )?;
    if constants.key.strict() && lane.strict_key_comparison {

        let ceiling = select_or_constant(
            constraint_system.namespace(|| "gated_ceiling"),
            &both_active,
            &current_key,
            Fr::ONE,
        )?;
        enforce_less(
            constraint_system.namespace(|| constants.key.predicate()),
            &previous_key,
            &ceiling,
            constants.packed_key_bits(),
        )?;
    } else {
        enforce_less_or_equal(
            constraint_system.namespace(|| "the sort key must not decrease"),
            &previous_key,
            &current_key,
            constants.packed_key_bits(),
        )?;
    }

    if !lane.assert_no_same_vehicle_overlap {
        return Ok(LaneWires { raw: fields.raw.clone(), gated: Some(fields) });
    }
    if let (Some(vehicle_slot), Some(end_slot)) = (slots.previous_vehicle_id, slots.previous_end) {
        enforce_no_same_vehicle_overlap(
            constraint_system,
            &state[vehicle_slot],
            &state[end_slot],
            &fields,
            &both_active,
            constants,
        )?;
    }

    Ok(LaneWires { raw: fields.raw.clone(), gated: Some(fields) })
}

impl StepCircuit<Fr> for MergedStep {
    fn arity(&self) -> usize {
        STATE_LENGTH
    }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        constraint_system: &mut CS,
        state: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {

        let next_record_index = enforce_increment(
            constraint_system.namespace(|| "advance_record_index"),
            &state[SLOT_RECORD_INDEX],
        )?;

        let is_final_row = is_equal(
            constraint_system.namespace(|| "is_final_row"),
            &next_record_index,
            &state[SLOT_RECORD_COUNT_TOTAL],
        )?;
        let first_index =
            alloc_constant(constraint_system.namespace(|| "first_record_index"), &Fr::ZERO)?;
        let is_first_row = is_equal(
            constraint_system.namespace(|| "is_first_row"),
            &state[SLOT_RECORD_INDEX],
            &first_index,
        )?;
        let zero = AllocatedNum::alloc(constraint_system.namespace(|| "zero"), || Ok(Fr::ZERO))?;
        constraint_system.enforce(
            || "zero == 0",
            |lc| lc + zero.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        let enabled = self.enabled;
        let pad = if enabled.any_grand_product() {
            let pad = AllocatedNum::alloc(constraint_system.namespace(|| "grand_product_pad"), || {
                Ok(self.pad)
            })?;
            enforce_nonzero(constraint_system.namespace(|| "pad_nonzero"), &pad)?;
            Some(pad)
        } else {
            None
        };

        let anchor = RowVariables::allocate(constraint_system, &self.anchor, &self.constants.anchor)?;
        if enabled.p1 {
            enforce_identifiers_present(constraint_system, &anchor)?;
        }
        if enabled.p2 {
            enforce_time_window(constraint_system, &anchor, &self.constants.anchor)?;
        }
        if enabled.p3 {
            enforce_hubs_whitelisted(constraint_system, &anchor, &self.constants.anchor)?;
        }

        let (next_active_count, next_positive_load_count) = if enabled.p4 {
            accumulate_and_assert_load_ratio(
                constraint_system,
                &anchor,
                &state[SLOT_ACTIVE_COUNT],
                &state[SLOT_POSITIVE_LOAD_COUNT],
                &is_final_row,
                &zero,
                &self.constants.anchor,
            )?
        } else {
            (
                state[SLOT_ACTIVE_COUNT].clone(),
                state[SLOT_POSITIVE_LOAD_COUNT].clone(),
            )
        };

        let anchor_fields = anchor.field_elements();

        let anchor_record = if enabled.needs_record_fingerprint() {
            Some(record_fingerprint(
                constraint_system.namespace(|| "anchor_record_fingerprint"),
                &state[SLOT_FINGERPRINT_CHALLENGE],
                &anchor_fields,
            )?)
        } else {
            None
        };

        let (next_fingerprint, next_power_of_stride) = match &anchor_record {
            Some(record) if enabled.fingerprint => (
                fold_record(
                    constraint_system.namespace(|| "fold_fingerprint"),
                    &state[SLOT_FINGERPRINT],
                    &state[SLOT_POWER_OF_STRIDE],
                    record,
                )?,
                state[SLOT_POWER_OF_STRIDE].mul(
                    constraint_system.namespace(|| "advance_power_of_stride"),
                    &state[SLOT_RECORD_STRIDE],
                )?,
            ),
            _ => (
                state[SLOT_FINGERPRINT].clone(),
                state[SLOT_POWER_OF_STRIDE].clone(),
            ),
        };

        let key1 = if enabled.sigma1() {
            Some(enforce_view(
                &mut constraint_system.namespace(|| "key1"),
                &self.key1,
                state,
                &KEY1_SLOTS,
                &self.constants.key1,
                LaneAblation {
                    enforce_ordering: enabled.order1,
                    strict_key_comparison: true,
                    assert_no_same_vehicle_overlap: enabled.p5,
                },
            )?)
        } else {
            None
        };
        let key2 = if enabled.sigma2() {
            Some(enforce_view(
                &mut constraint_system.namespace(|| "key2"),
                &self.key2,
                state,
                &KEY2_SLOTS,
                &self.constants.key2,
                LaneAblation {
                    enforce_ordering: enabled.order2,
                    strict_key_comparison: enabled.p6,
                    assert_no_same_vehicle_overlap: false,
                },
            )?)
        } else {
            None
        };

        let absent_lane: [AllocatedNum<Fr>; FIELDS_PER_RECORD] =
            std::array::from_fn(|_| zero.clone());
        let next_commitment_chain = if enabled.commitment {
            let tuple = [
                anchor_fields.clone(),
                key1.as_ref().map_or_else(|| absent_lane.clone(), |lane| lane.raw.clone()),
                key2.as_ref().map_or_else(|| absent_lane.clone(), |lane| lane.raw.clone()),
            ];
            absorb_tuple_in_circuit(
                constraint_system,
                &self.constants.tuple_constants,
                &state[SLOT_COMMITMENT_CHAIN],
                &tuple,
            )?
        } else {
            state[SLOT_COMMITMENT_CHAIN].clone()
        };

        let mut next_grand_product_anchor = zero.clone();
        let mut next_grand_product_key1 = zero.clone();
        let mut next_grand_product_key2 = zero.clone();

        if let (Some(pad), Some(anchor_record)) = (&pad, &anchor_record) {

            let folded_anchor = fold_one_product(
                constraint_system,
                "grand_product_anchor",
                &is_first_row,
                pad,
                &state[SLOT_GRAND_PRODUCT_ANCHOR],
                &state[SLOT_GRAND_PRODUCT_CHALLENGE],
                anchor_record,
            )?;

            for (lane, wires, slot, product_name, link_name, published) in [
                (
                    "key1",
                    enabled.product1.then_some(key1.as_ref()).flatten(),
                    SLOT_GRAND_PRODUCT_KEY1,
                    "grand_product_key1",
                    "key1_grand_product_matches",
                    &mut next_grand_product_key1,
                ),
                (
                    "key2",
                    enabled.product2.then_some(key2.as_ref()).flatten(),
                    SLOT_GRAND_PRODUCT_KEY2,
                    "grand_product_key2",
                    "key2_grand_product_matches",
                    &mut next_grand_product_key2,
                ),
            ] {
                let Some(wires) = wires else { continue };
                let record = record_fingerprint(
                    constraint_system.namespace(|| format!("{lane}_record_fingerprint")),
                    &state[SLOT_FINGERPRINT_CHALLENGE],
                    &wires.raw,
                )?;
                let folded = fold_one_product(
                    constraint_system,
                    product_name,
                    &is_first_row,
                    pad,
                    &state[slot],
                    &state[SLOT_GRAND_PRODUCT_CHALLENGE],
                    &record,
                )?;
                constraint_system.enforce(
                    || link_name,
                    |_| is_final_row.lc(CS::one(), Fr::ONE),
                    |lc| lc + folded.get_variable() - folded_anchor.get_variable(),
                    |lc| lc,
                );
                *published = select(
                    constraint_system.namespace(|| format!("publish_{product_name}")),
                    &is_final_row,
                    &zero,
                    &folded,
                )?;
            }

            next_grand_product_anchor = select(
                constraint_system.namespace(|| "publish_grand_product_anchor"),
                &is_final_row,
                &zero,
                &folded_anchor,
            )?;
        }

        let carried = |slot: usize| state[slot].clone();
        let (key1_active, key1_key, key1_vehicle, key1_end) =
            match key1.as_ref().and_then(|lane| lane.gated.as_ref()) {
                Some(fields) => (
                    fields.raw[FIELD_ACTIVE].clone(),
                    fields.packed_key.clone(),
                    fields.vehicle_id.clone(),
                    fields.end.clone(),
                ),
                None => (
                    carried(SLOT_KEY1_PREVIOUS_ACTIVE),
                    carried(SLOT_KEY1_PREVIOUS_PACKED_KEY),
                    carried(SLOT_KEY1_PREVIOUS_VEHICLE_ID),
                    carried(SLOT_KEY1_PREVIOUS_END),
                ),
            };
        let (key2_active, key2_key) =
            match key2.as_ref().and_then(|lane| lane.gated.as_ref()) {
                Some(fields) => (
                    fields.raw[FIELD_ACTIVE].clone(),
                    fields.packed_key.clone(),
                ),
                None => (
                    carried(SLOT_KEY2_PREVIOUS_ACTIVE),
                    carried(SLOT_KEY2_PREVIOUS_PACKED_KEY),
                ),
            };

        Ok(vec![
            next_record_index,
            next_commitment_chain,
            next_fingerprint,
            next_power_of_stride,
            state[SLOT_FINGERPRINT_CHALLENGE].clone(),
            state[SLOT_RECORD_STRIDE].clone(),
            state[SLOT_RECORD_COUNT_TOTAL].clone(),
            next_active_count,
            next_positive_load_count,
            state[SLOT_GRAND_PRODUCT_CHALLENGE].clone(),
            next_grand_product_anchor,
            next_grand_product_key1,
            next_grand_product_key2,
            key1_active,
            key1_key,
            key1_vehicle,
            key1_end,
            key2_active,
            key2_key,
        ])
    }
}

fn fold_one_product<CS: ConstraintSystem<Fr>>(
    constraint_system: &mut CS,
    name: &str,
    is_first_row: &Boolean,
    pad: &AllocatedNum<Fr>,
    carried: &AllocatedNum<Fr>,
    challenge: &AllocatedNum<Fr>,
    record: &AllocatedNum<Fr>,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let base = select(
        constraint_system.namespace(|| format!("{name}_base")),
        is_first_row,
        pad,
        carried,
    )?;
    fold_grand_product(
        constraint_system.namespace(|| format!("fold_{name}")),
        &base,
        challenge,
        record,
    )
}

pub fn initial_state(
    fingerprint_challenge: Fr,
    record_stride: Fr,
    grand_product_challenge: Fr,
    row_count: usize,
) -> Vec<Fr> {
    let mut state = vec![Fr::ZERO; STATE_LENGTH];

    state[SLOT_COMMITMENT_CHAIN] = initial_chain();
    state[SLOT_POWER_OF_STRIDE] = Fr::ONE;
    state[SLOT_FINGERPRINT_CHALLENGE] = fingerprint_challenge;
    state[SLOT_RECORD_STRIDE] = record_stride;
    state[SLOT_RECORD_COUNT_TOTAL] = Fr::from(row_count as u64);
    state[SLOT_GRAND_PRODUCT_CHALLENGE] = grand_product_challenge;

    state[SLOT_GRAND_PRODUCT_ANCHOR] = Fr::ONE;
    state[SLOT_GRAND_PRODUCT_KEY1] = Fr::ONE;
    state[SLOT_GRAND_PRODUCT_KEY2] = Fr::ONE;
    state[SLOT_KEY1_PREVIOUS_ACTIVE] = Fr::ONE;
    state[SLOT_KEY2_PREVIOUS_ACTIVE] = Fr::ONE;
    state
}

pub fn steps_from_views(
    anchor: Vec<PreparedRow>,
    key1: Vec<PreparedRow>,
    key2: Vec<PreparedRow>,
    pad: Fr,
    constants: &MergedConstants,
) -> Result<Vec<MergedStep>, String> {
    steps_from_views_enforcing(anchor, key1, key2, pad, constants, dataset::Enabled::all())
}

pub fn steps_from_views_enforcing(
    anchor: Vec<PreparedRow>,
    key1: Vec<PreparedRow>,
    key2: Vec<PreparedRow>,
    pad: Fr,
    constants: &MergedConstants,
    enabled: dataset::Enabled,
) -> Result<Vec<MergedStep>, String> {
    enabled.validate()?;
    if anchor.len() != key1.len() || anchor.len() != key2.len() {
        return Err(format!(
            "the traversals have {}, {} and {} rows; folding them in lockstep needs one row of \
             each per step",
            anchor.len(),
            key1.len(),
            key2.len()
        ));
    }
    Ok(anchor
        .into_iter()
        .zip(key1)
        .zip(key2)
        .map(|((anchor, key1), key2)| MergedStep {
            anchor,
            key1,
            key2,
            pad,
            constants: constants.clone(),
            enabled,
        })
        .collect())
}
