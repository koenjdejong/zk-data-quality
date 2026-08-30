use crate::predicates::{field_elements, Record};

pub global INITIAL_CHAIN: Field = 0;

pub fn absorb_row(chain: Field, row: Record) -> Field {
    let fields = field_elements(row);
    poseidon::poseidon2::Poseidon2::hash(
        [
            chain,
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7],
        ],
        9,
    )
}

pub fn absorb_step(chain: Field, anchor: Record, key1: Record, key2: Record) -> Field {
    let a = field_elements(anchor);
    let b = field_elements(key1);
    let c = field_elements(key2);
    poseidon::poseidon2::Poseidon2::hash(
        [
            chain,
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
        ],
        25,
    )
}

pub fn absent_row() -> Record {
    Record {
        record_id: 0,
        active: false,
        vehicle_id: 0,
        start: 0,
        end: 0,
        origin_hub: 0,
        destination_hub: 0,
        load_kg: 0,
    }
}
