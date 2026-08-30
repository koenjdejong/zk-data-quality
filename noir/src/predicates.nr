use crate::constants::{
    ALLOWED_HUBS, ENFORCE_P1, ENFORCE_P2, ENFORCE_P3, MEMBERSHIP_OR_CHAIN,
    MEMBERSHIP_PRODUCT, POSITIVE_LOAD_RATIO_DENOMINATOR, POSITIVE_LOAD_RATIO_NUMERATOR,
    ROW_COUNT, TIME_MAXIMUM, TIME_MINIMUM,
};


pub struct Record {
    pub record_id: Field,
    pub active: bool,
    pub vehicle_id: u64,
    pub start: u64,
    pub end: u64,
    pub origin_hub: u64,
    pub destination_hub: u64,
    pub load_kg: u64,
}

pub fn field_elements(row: Record) -> [Field; 8] {
    [
        row.record_id,
        row.active as Field,
        row.vehicle_id as Field,
        row.start as Field,
        row.end as Field,
        row.origin_hub as Field,
        row.destination_hub as Field,
        row.load_kg as Field,
    ]
}

pub fn is_whitelisted_or_chain(hub: u64) -> bool {
    let mut whitelisted = false;
    for allowed in ALLOWED_HUBS {
        whitelisted = whitelisted | (hub == allowed);
    }
    whitelisted
}

pub fn is_whitelisted_product(hub: Field) -> bool {
    let mut acc: Field = 1;
    for allowed in ALLOWED_HUBS {
        acc = acc * (hub - allowed as Field);
    }
    acc == 0
}

unconstrained fn find_hub_index(hub: Field) -> u32 {
    let mut idx: u32 = 0;
    for i in 0..ALLOWED_HUBS.len() {
        if ALLOWED_HUBS[i] as Field == hub {
            idx = i as u32;
            break;
        }
    }
    idx
}

pub fn is_whitelisted_lookup(hub: Field) -> bool {
    // Safety: find_hub_index
    let idx = unsafe { find_hub_index(hub) };
    ALLOWED_HUBS[idx] as Field == hub
}

pub fn is_whitelisted(hub: u64) -> bool {
    if MEMBERSHIP_OR_CHAIN {
        is_whitelisted_or_chain(hub)
    } else if MEMBERSHIP_PRODUCT {
        is_whitelisted_product(hub as Field)
    } else {
        is_whitelisted_lookup(hub as Field)
    }
}

pub fn identifiers_present(row: Record) -> bool {
    (row.record_id != 0) & (row.vehicle_id != 0)
}

pub fn time_window(row: Record) -> bool {
    (TIME_MINIMUM <= row.start) & (row.end <= TIME_MAXIMUM) & (row.start < row.end)
}

pub fn hubs_whitelisted(row: Record) -> bool {
    is_whitelisted(row.origin_hub) & is_whitelisted(row.destination_hub)
}

pub fn enforce_row_local_predicates(row: Record) {
    if ENFORCE_P1 {
        assert(!row.active | identifiers_present(row), "P1 identifiers_present");
    }
    if ENFORCE_P2 {
        assert(!row.active | time_window(row), "P2 time_window");
    }
    if ENFORCE_P3 {
        assert(!row.active | hubs_whitelisted(row), "P3 hubs_whitelisted");
    }
}

pub struct LoadRatio {
    pub active_count: u64,
    pub positive_load_count: u64,
}

impl LoadRatio {
    pub fn new() -> Self {
        LoadRatio { active_count: 0, positive_load_count: 0 }
    }

    pub fn absorb_row(self, row: Record) -> Self {
        let counts = row.active & (row.load_kg > 0);
        LoadRatio {
            active_count: self.active_count + row.active as u64,
            positive_load_count: self.positive_load_count + counts as u64,
        }
    }

    pub fn holds(self) -> bool {
        self.positive_load_count * POSITIVE_LOAD_RATIO_DENOMINATOR
            >= POSITIVE_LOAD_RATIO_NUMERATOR * self.active_count
    }
}

pub fn key_vehicle_and_start_not_decreasing(previous: Record, current: Record) -> bool {
    (previous.vehicle_id < current.vehicle_id)
        | ((previous.vehicle_id == current.vehicle_id) & (previous.start <= current.start))
}

pub fn active_rows_form_a_prefix(previous: Record, current: Record) -> bool {
    !(current.active & !previous.active)
}

pub fn enforce_sorted_by_vehicle_and_start<let N: u32>(view: [Record; N]) {
    for index in 0..N - 1 {
        let previous = view[index];
        let current = view[index + 1];
        assert(
            active_rows_form_a_prefix(previous, current),
            "sort proof: active rows must form a prefix",
        );
        let both_active = previous.active & current.active;
        assert(
            !both_active | key_vehicle_and_start_not_decreasing(previous, current),
            "sort proof: the K1 key decreased",
        );
    }
}

pub fn enforce_no_same_vehicle_overlap_all_pairs(rows: [Record; ROW_COUNT]) {
    for first in 0..ROW_COUNT {
        for second in first + 1..ROW_COUNT {
            let earlier = rows[first];
            let later = rows[second];
            let applies =
                earlier.active & later.active & (earlier.vehicle_id == later.vehicle_id);

            let disjoint = (earlier.end <= later.start) | (later.end <= earlier.start);
            assert(!applies | disjoint, "P5 no_same_vehicle_overlap (all pairs)");
        }
    }
}

pub fn enforce_record_ids_strictly_increasing<let N: u32>(view: [Record; N]) {
    for index in 0..N - 1 {
        let previous = view[index];
        let current = view[index + 1];
        assert(
            active_rows_form_a_prefix(previous, current),
            "sort proof: active rows must form a prefix",
        );

        let both_active = previous.active & current.active;
        let previous_id: Field = if both_active { previous.record_id } else { 0 };
        let current_id: Field = if both_active { current.record_id } else { 0 };
        assert(
            !both_active | ((previous_id as u64) < (current_id as u64)),
            "P6 record_ids_strictly_increasing",
        );
    }
}

pub fn enforce_record_ids_not_decreasing<let N: u32>(view: [Record; N]) {
    for index in 0..N - 1 {
        let previous = view[index];
        let current = view[index + 1];
        assert(
            active_rows_form_a_prefix(previous, current),
            "sort proof: active rows must form a prefix",
        );

        let both_active = previous.active & current.active;
        let previous_id: Field = if both_active { previous.record_id } else { 0 };
        let current_id: Field = if both_active { current.record_id } else { 0 };
        assert(
            !both_active | ((previous_id as u64) <= (current_id as u64)),
            "sort proof: the K2 key decreased",
        );
    }
}

pub fn enforce_no_same_vehicle_overlap<let N: u32>(view: [Record; N]) {
    for index in 0..N - 1 {
        let previous = view[index];
        let current = view[index + 1];
        let applies =
            previous.active & current.active & (previous.vehicle_id == current.vehicle_id);
        assert(!applies | (previous.end <= current.start), "P5 no_same_vehicle_overlap");
    }
}
