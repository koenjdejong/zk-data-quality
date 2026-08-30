from shared.reference import derive_challenges, fingerprint, transcript_commitment
from shared.schema import BN254_SCALAR_FIELD_MODULUS, FIELDS_PER_RECORD, Record


def blinder_position(records) -> int:
    positions = [index for index, record in enumerate(records) if not record.active]
    assert len(positions) == 1, "an honest dataset has exactly one blinder row"
    return positions[0]


def solve_for_blinder_identifier(records, position: int, target: int, challenge: int) -> int:
    without_blinder = list(records)
    without_blinder[position] = Record(
        record_id=0,
        active=False,
        vehicle_id=0,
        start=0,
        end=0,
        origin_hub=0,
        destination_hub=0,
        load_kg=0,
    )
    remainder = fingerprint(without_blinder, challenge)
    coefficient = pow(challenge, FIELDS_PER_RECORD * position, BN254_SCALAR_FIELD_MODULUS)
    inverse = pow(coefficient, -1, BN254_SCALAR_FIELD_MODULUS)
    return (target - remainder) * inverse % BN254_SCALAR_FIELD_MODULUS


def substitute_blinder(records, position: int, identifier: int):
    forged = list(records)
    original = forged[position]
    forged[position] = Record(
        record_id=identifier,
        active=original.active,
        vehicle_id=original.vehicle_id,
        start=original.start,
        end=original.end,
        origin_hub=original.origin_hub,
        destination_hub=original.destination_hub,
        load_kg=original.load_kg,
    )
    return tuple(forged)


def challenge_ordering(clean_records, dirty_records) -> dict:
    assert any(
        clean != dirty
        for clean, dirty in zip(clean_records, dirty_records)
        if clean.active or dirty.active
    ), "the forgery must conceal something: these datasets differ only in their padding"
    chosen_challenge = 0x5EED
    published = fingerprint(clean_records, chosen_challenge)
    position = blinder_position(dirty_records)
    forged_identifier = solve_for_blinder_identifier(
        dirty_records, position, published, chosen_challenge
    )
    forged_records = substitute_blinder(dirty_records, position, forged_identifier)
    forged_fingerprint = fingerprint(forged_records, chosen_challenge)

    derived_challenge, _ = derive_challenges([transcript_commitment([forged_records])])
    published_under_derived = fingerprint(clean_records, derived_challenge)
    forged_under_derived = fingerprint(forged_records, derived_challenge)

    return {
        "chosen_challenge": hex(chosen_challenge),
        "forged_identifier_bits": forged_identifier.bit_length(),
        "forgery_succeeds_under_a_chosen_challenge": forged_fingerprint == published,
        "derived_challenge": hex(derived_challenge),
        "forgery_fails_once_the_challenge_is_derived": forged_under_derived
        != published_under_derived,
    }
