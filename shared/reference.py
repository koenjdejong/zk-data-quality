from hashlib import sha3_256

from shared.schema import Dataset
from shared.schema import (
    ALLOWED_HUBS,
    COMPOSITE_SORT_KEYS,
    BN254_SCALAR_FIELD_MODULUS,
    FIAT_SHAMIR_DOMAIN,
    FIELDS_PER_RECORD,
    POSITIVE_LOAD_RATIO_DENOMINATOR,
    POSITIVE_LOAD_RATIO_NUMERATOR,
    SORT_KEYS,
    TIME_MAXIMUM,
    TIME_MINIMUM,
    Record,
)

def encode_field_element(value: int) -> bytes:
    return (value % BN254_SCALAR_FIELD_MODULUS).to_bytes(32, "big")


def traversals_of(dataset) -> tuple[tuple[Record, ...], ...]:
    return (dataset.presented_records, *(dataset.view(name) for name in SORT_KEYS))


def transcript_commitment(traversals) -> int:
    traversals = tuple(tuple(traversal) for traversal in traversals)
    lengths = {len(traversal) for traversal in traversals}
    assert len(lengths) == 1, f"traversals must be index-aligned, got lengths {sorted(lengths)}"

    chain = 0
    for index in range(lengths.pop()):
        block = b"".join(
            encode_field_element(value)
            for traversal in traversals
            for value in traversal[index].to_field_elements()
        )
        chain = (
            int.from_bytes(
                sha3_256(FIAT_SHAMIR_DOMAIN + b"chain" + encode_field_element(chain) + block).digest(),
                "big",
            )
            % BN254_SCALAR_FIELD_MODULUS
        )
    return chain


def derive_challenges(commitments) -> tuple[int, int]:
    commitments = tuple(commitments)
    assert commitments, "a challenge needs at least one commitment to be derived from"
    transcript = FIAT_SHAMIR_DOMAIN + b"commitments" + b"".join(
        encode_field_element(commitment) for commitment in commitments
    )
    fingerprint_challenge = (
        int.from_bytes(sha3_256(transcript + b"fingerprint").digest(), "big")
        % BN254_SCALAR_FIELD_MODULUS
    )
    grand_product_challenge = (
        int.from_bytes(sha3_256(transcript + b"grand-product").digest(), "big")
        % BN254_SCALAR_FIELD_MODULUS
    )
    return fingerprint_challenge, grand_product_challenge


def challenges_for(dataset) -> tuple[int, int]:
    return derive_challenges([transcript_commitment(traversals_of(dataset))])


def record_stride(fingerprint_challenge: int) -> int:
    return pow(fingerprint_challenge, FIELDS_PER_RECORD, BN254_SCALAR_FIELD_MODULUS)


def record_fingerprint(record: Record, fingerprint_challenge: int) -> int:
    total = 0
    power = 1
    for value in record.to_field_elements():
        total = (total + value % BN254_SCALAR_FIELD_MODULUS * power) % BN254_SCALAR_FIELD_MODULUS
        power = power * fingerprint_challenge % BN254_SCALAR_FIELD_MODULUS
    return total


def fingerprint(records, fingerprint_challenge: int) -> int:
    total = 0
    power = 1
    for record in records:
        for value in record.to_field_elements():
            total = (
                total + value % BN254_SCALAR_FIELD_MODULUS * power
            ) % BN254_SCALAR_FIELD_MODULUS
            power = power * fingerprint_challenge % BN254_SCALAR_FIELD_MODULUS
    return total


def grand_product(
    records,
    fingerprint_challenge: int,
    grand_product_challenge: int,
    blinding_element: int,
) -> int:
    assert blinding_element % BN254_SCALAR_FIELD_MODULUS != 0, (
        "the pad must be non-zero: zero collapses the product whatever the data, and lets a prover "
        "make every traversal agree vacuously"
    )
    product = blinding_element % BN254_SCALAR_FIELD_MODULUS
    for record in records:
        difference = (
            grand_product_challenge - record_fingerprint(record, fingerprint_challenge)
        ) % BN254_SCALAR_FIELD_MODULUS
        product = product * difference % BN254_SCALAR_FIELD_MODULUS
    return product


def identifiers_present(records) -> bool:
    return all(
        record.record_id != 0 and record.vehicle_id != 0 for record in records if record.active
    )


def time_window(records) -> bool:
    return all(
        TIME_MINIMUM <= record.start and record.end <= TIME_MAXIMUM and record.start < record.end
        for record in records
        if record.active
    )


def hubs_whitelisted(records, allowed_hubs=ALLOWED_HUBS) -> bool:
    allowed = set(allowed_hubs)
    return all(
        record.origin_hub in allowed and record.destination_hub in allowed
        for record in records
        if record.active
    )


def positive_load_ratio(records) -> bool:
    active_count = sum(1 for record in records if record.active)
    positive_count = sum(1 for record in records if record.active and record.load_kg > 0)
    return (
        positive_count * POSITIVE_LOAD_RATIO_DENOMINATOR
        >= POSITIVE_LOAD_RATIO_NUMERATOR * active_count
    )


def satisfies_naive_adjacency(view) -> bool:
    return all(
        not (previous.active and current.active and previous.vehicle_id == current.vehicle_id)
        or previous.end <= current.start
        for previous, current in zip(view, view[1:])
    )


def record_ids_strictly_increasing(view) -> bool:
    return all(
        not (previous.active and current.active) or previous.record_id < current.record_id
        for previous, current in zip(view, view[1:])
    )


def satisfies_sortedness(view, sort_key_name: str) -> bool:
    sort_key = SORT_KEYS[sort_key_name]
    return all(
        sort_key(previous) <= sort_key(current) for previous, current in zip(view, view[1:])
    )


def satisfies_active_prefix(view) -> bool:
    return all(
        not (current.active and not previous.active)
        for previous, current in zip(view, view[1:])
    )


def satisfies_composite_sortedness(view, sort_key_name: str) -> bool:
    composite = COMPOSITE_SORT_KEYS[sort_key_name]
    if not satisfies_active_prefix(view):
        return False
    return all(
        not (previous.active and current.active) or composite(previous) <= composite(current)
        for previous, current in zip(view, view[1:])
    )


def has_same_vehicle_overlap(records) -> bool:
    active = [record for record in records if record.active]
    return any(
        first.vehicle_id == second.vehicle_id
        and first.start < second.end
        and second.start < first.end
        for index, first in enumerate(active)
        for second in active[index + 1 :]
    )


def evaluate(dataset: Dataset) -> dict[str, bool]:
    presented = dataset.presented_records
    view_key1 = dataset.view("key1")
    view_key2 = dataset.view("key2")
    fingerprint_challenge, grand_product_challenge = challenges_for(dataset)
    blinding_element = dataset.grand_product_blinding_element
    anchor_grand_product = grand_product(
        presented, fingerprint_challenge, grand_product_challenge, blinding_element
    )
    return {
        "identifiers_present": identifiers_present(presented),
        "time_window": time_window(presented),
        "hubs_whitelisted": hubs_whitelisted(presented, dataset.allowed_hubs),
        "positive_load_ratio": positive_load_ratio(presented),
        "no_same_vehicle_overlap": satisfies_naive_adjacency(view_key1),
        "record_ids_strictly_increasing": record_ids_strictly_increasing(view_key2),
        "sorted_by_key1": satisfies_sortedness(view_key1, "key1"),
        "sorted_by_key2": satisfies_sortedness(view_key2, "key2"),
        "key1_grand_product_matches": grand_product(
            view_key1, fingerprint_challenge, grand_product_challenge, blinding_element
        )
        == anchor_grand_product,
        "key2_grand_product_matches": grand_product(
            view_key2, fingerprint_challenge, grand_product_challenge, blinding_element
        )
        == anchor_grand_product,
    }


def failing_checks(dataset: Dataset) -> set[str]:
    return {name for name, holds in evaluate(dataset).items() if not holds}
