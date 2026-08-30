pub mod commitment;
pub mod constants;
pub mod gp;
pub mod predicates;
pub mod rlc;

use commitment::{absent_row, absorb_row, absorb_step, INITIAL_CHAIN};
use constants::{
    ALL_PAIRS, COMMITMENT, ENFORCE_P4, ENFORCE_P5, ENFORCE_P6, FINGERPRINT, KEY1_ROWS, KEY2_ROWS,
    ORDER1, ORDER2, PRODUCT1, PRODUCT2, ROW_COUNT, SIGMA1, SIGMA2,
};
use gp::grand_product;
use rlc::{record_fingerprint, record_stride};
use predicates::{
    enforce_no_same_vehicle_overlap, enforce_no_same_vehicle_overlap_all_pairs,
    enforce_record_ids_not_decreasing, enforce_record_ids_strictly_increasing,
    enforce_row_local_predicates, enforce_sorted_by_vehicle_and_start, LoadRatio, Record,
};

fn main(
    rows: [Record; ROW_COUNT],

    sorted_by_vehicle_and_start: [Record; KEY1_ROWS],

    sorted_by_record_id: [Record; KEY2_ROWS],

    grand_product_blinding_element: Field,
    fingerprint_challenge: pub Field,
    grand_product_challenge: pub Field,
) -> pub [Field; 2] {
    let stride = record_stride(fingerprint_challenge);

    let mut commitment_chain = INITIAL_CHAIN;
    let mut fingerprint: Field = 0;
    let mut power_of_stride: Field = 1;
    let mut load_ratio = LoadRatio::new();

    for index in 0..ROW_COUNT {
        let row = rows[index];
        enforce_row_local_predicates(row);

        if COMMITMENT {
            if ALL_PAIRS {
                commitment_chain = absorb_row(commitment_chain, row);
            } else {

                let key1_index = if SIGMA1 { index } else { 0 };
                let key2_index = if SIGMA2 { index } else { 0 };
                let key1 =
                    if SIGMA1 { sorted_by_vehicle_and_start[key1_index] } else { absent_row() };
                let key2 = if SIGMA2 { sorted_by_record_id[key2_index] } else { absent_row() };
                commitment_chain = absorb_step(commitment_chain, row, key1, key2);
            }
        }

        if FINGERPRINT {
            fingerprint += power_of_stride * record_fingerprint(fingerprint_challenge, row);
            power_of_stride = power_of_stride * stride;
        }

        if ENFORCE_P4 {
            load_ratio = load_ratio.absorb_row(row);
        }
    }

    if ENFORCE_P4 {
        assert(load_ratio.holds(), "P4 positive_load_ratio");
    }

    if ALL_PAIRS {

        enforce_no_same_vehicle_overlap_all_pairs(rows);
    } else if SIGMA1 | SIGMA2 {

        let anchor = if PRODUCT1 | PRODUCT2 {
            assert(grand_product_blinding_element != 0, "the grand-product pad must be non-zero");
            grand_product(
                rows,
                fingerprint_challenge,
                grand_product_challenge,
                grand_product_blinding_element,
            )
        } else {
            0
        };

        if SIGMA1 {

            if ORDER1 {
                enforce_sorted_by_vehicle_and_start(sorted_by_vehicle_and_start);
                if ENFORCE_P5 {
                    enforce_no_same_vehicle_overlap(sorted_by_vehicle_and_start);
                }
            }
            if PRODUCT1 {
                assert(
                    grand_product(
                        sorted_by_vehicle_and_start,
                        fingerprint_challenge,
                        grand_product_challenge,
                        grand_product_blinding_element,
                    ) == anchor,
                    "the K1 view is not a permutation of the anchor traversal",
                );
            }
        }

        if SIGMA2 {

            if ORDER2 {
                if ENFORCE_P6 {
                    enforce_record_ids_strictly_increasing(sorted_by_record_id);
                } else {
                    enforce_record_ids_not_decreasing(sorted_by_record_id);
                }
            }
            if PRODUCT2 {
                assert(
                    grand_product(
                        sorted_by_record_id,
                        fingerprint_challenge,
                        grand_product_challenge,
                        grand_product_blinding_element,
                    ) == anchor,
                    "the K2 view is not a permutation of the anchor traversal",
                );
            }
        }
    }

    [commitment_chain, fingerprint]
}
