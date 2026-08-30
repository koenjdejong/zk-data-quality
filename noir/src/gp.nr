use crate::predicates::Record;
use crate::rlc::record_fingerprint;

pub fn grand_product<let N: u32>(
    view: [Record; N],
    fingerprint_challenge: Field,
    grand_product_challenge: Field,
    blinding_element: Field,
) -> Field {
    let mut product: Field = blinding_element;
    for row in view {
        product *= grand_product_challenge - record_fingerprint(fingerprint_challenge, row);
    }
    product
}
