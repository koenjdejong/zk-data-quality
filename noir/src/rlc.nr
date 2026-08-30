use crate::predicates::{field_elements, Record};

pub global FIELDS_PER_RECORD: u32 = 8;

pub fn record_fingerprint(challenge: Field, row: Record) -> Field {
    let fields = field_elements(row);
    let mut accumulator = fields[FIELDS_PER_RECORD - 1];
    for offset in 0..FIELDS_PER_RECORD - 1 {
        accumulator = accumulator * challenge + fields[FIELDS_PER_RECORD - 2 - offset];
    }
    accumulator
}

pub fn record_stride(challenge: Field) -> Field {
    let mut stride: Field = 1;
    for _ in 0..FIELDS_PER_RECORD {
        stride = stride * challenge;
    }
    stride
}
