import random
from dataclasses import dataclass
from typing import Callable

from shared.schema import (
    ALLOWED_HUBS,
    BN254_SCALAR_FIELD_MODULUS,
    RECORDS_PER_VEHICLE_DEFAULT,
    SORT_KEYS,
    Dataset,
    Record,
    sorted_permutation,
)

TIME_BASE = 1_000
SLOT_STRIDE = 10_000
SLOT_DURATION = 3_600
VEHICLE_TIME_OFFSET_MULTIPLIER = 1_237
VEHICLE_TIME_OFFSET_MODULUS = 1_000_000

ZERO_LOAD_PERIOD = 17
LOAD_KG_BASE = 12_000
LOAD_KG_VARIATION_MULTIPLIER = 7
LOAD_KG_VARIATION_MODULUS = 20_000

DEFAULT_SEED = 20260730
DEFAULT_BLINDING_SEED = 1

PRESENTATION_SHUFFLE_ATTEMPTS = 64


def generate_active_records(
    record_count: int,
    records_per_vehicle: int = RECORDS_PER_VEHICLE_DEFAULT,
    seed: int = DEFAULT_SEED,
    allowed_hubs=ALLOWED_HUBS,
) -> list[Record]:
    if record_count < 0:
        raise ValueError("record_count must not be negative")
    if records_per_vehicle < 1:
        raise ValueError("records_per_vehicle must be at least 1")

    record_ids = list(range(1, record_count + 1))
    random.Random(seed).shuffle(record_ids)

    records = []
    for record_index in range(record_count):
        vehicle_index = record_index // records_per_vehicle
        position_in_vehicle = record_index % records_per_vehicle
        vehicle_time_offset = (
            vehicle_index * VEHICLE_TIME_OFFSET_MULTIPLIER
        ) % VEHICLE_TIME_OFFSET_MODULUS
        start = TIME_BASE + vehicle_time_offset + position_in_vehicle * SLOT_STRIDE
        has_zero_load = record_index % ZERO_LOAD_PERIOD == ZERO_LOAD_PERIOD - 1
        records.append(
            Record(
                record_id=record_ids[record_index],
                active=True,
                vehicle_id=vehicle_index + 1,
                start=start,
                end=start + SLOT_DURATION,
                origin_hub=allowed_hubs[record_index % len(allowed_hubs)],
                destination_hub=allowed_hubs[(record_index + 3) % len(allowed_hubs)],
                load_kg=(
                    0
                    if has_zero_load
                    else LOAD_KG_BASE
                    + (record_index * LOAD_KG_VARIATION_MULTIPLIER) % LOAD_KG_VARIATION_MODULUS
                ),
            )
        )
    return records


def generate_blinder_record(blinding_seed: int = DEFAULT_BLINDING_SEED) -> Record:
    return Record(
        record_id=random.Random(blinding_seed).randrange(BN254_SCALAR_FIELD_MODULUS),
        active=False,
        vehicle_id=0,
        start=0,
        end=0,
        origin_hub=0,
        destination_hub=0,
        load_kg=0,
    )


def generate_grand_product_blinding(blinding_seed: int = DEFAULT_BLINDING_SEED) -> int:
    draws = random.Random(f"grand-product-blinding-{blinding_seed}")
    return draws.randrange(1, BN254_SCALAR_FIELD_MODULUS)


def present(rows, seed: int = DEFAULT_SEED) -> tuple[Record, ...]:
    identity = tuple(range(len(rows)))
    if len(rows) < 2:
        return tuple(rows)
    order = list(identity)
    shuffler = random.Random(seed)
    for _ in range(PRESENTATION_SHUFFLE_ATTEMPTS):
        shuffler.shuffle(order)
        presented = tuple(rows[position] for position in order)
        if all(
            sorted_permutation(presented, sort_key) != identity for sort_key in SORT_KEYS.values()
        ):
            return presented
    raise RuntimeError(
        f"could not find a presentation order distinct from both sorted views in "
        f"{PRESENTATION_SHUFFLE_ATTEMPTS} attempts (row_count={len(rows)})"
    )


NON_WHITELISTED_HUB = 999


def _use_a_non_whitelisted_hub(records):
    records[0] = records[0].with_changes(origin_hub=NON_WHITELISTED_HUB)
    return records


def _launder_a_non_whitelisted_hub(records):
    records[0] = records[0].with_changes(origin_hub=NON_WHITELISTED_HUB, active=False)
    return records


@dataclass(frozen=True, slots=True)
class Variant:
    target_check: str | None
    minimum_record_count: int
    mutate_rows: Callable | None


VARIANTS = {
    "honest": Variant(None, 0, None),
    "bad_hub": Variant("hubs_whitelisted", 1, _use_a_non_whitelisted_hub),
    "laundered": Variant(None, 1, _launder_a_non_whitelisted_hub),
}


def build(
    variant_name: str,
    record_count: int,
    records_per_vehicle: int = RECORDS_PER_VEHICLE_DEFAULT,
    seed: int = DEFAULT_SEED,
    blinding_seed: int = DEFAULT_BLINDING_SEED,
    allowed_hubs=ALLOWED_HUBS,
) -> Dataset:
    variant = VARIANTS[variant_name]
    if record_count < variant.minimum_record_count:
        raise ValueError(
            f"variant {variant_name!r} needs at least {variant.minimum_record_count} "
            f"records, got {record_count}"
        )

    records = generate_active_records(record_count, records_per_vehicle, seed, allowed_hubs)
    if variant.mutate_rows is not None:
        records = variant.mutate_rows(records)
    records.append(generate_blinder_record(blinding_seed))

    presented = present(records, seed)
    blinding_element = generate_grand_product_blinding(blinding_seed)
    return Dataset(
        variant=variant_name,
        record_count=record_count,
        records_per_vehicle=records_per_vehicle,
        seed=seed,
        blinding_seed=blinding_seed,
        presented_records=presented,
        permutation_to_key1=sorted_permutation(presented, SORT_KEYS["key1"]),
        permutation_to_key2=sorted_permutation(presented, SORT_KEYS["key2"]),
        allowed_hubs=tuple(allowed_hubs),
        target_predicate=variant.target_check,
        grand_product_blinding_element=blinding_element,
    )
