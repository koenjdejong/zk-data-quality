import math
from dataclasses import dataclass, replace
from typing import Callable

BN254_SCALAR_FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

FIELD_NAMES = (
    "record_id",
    "active",
    "vehicle_id",
    "start",
    "end",
    "origin_hub",
    "destination_hub",
    "load_kg",
)
FIELDS_PER_RECORD = len(FIELD_NAMES)

TIME_MINIMUM = 0
TIME_MAXIMUM = 2_000_000_000

ALLOWED_HUBS = (1, 7, 13, 42, 99, 128, 256, 500)


def scattered_hub_whitelist(size: int) -> tuple[int, ...]:
    if size == len(ALLOWED_HUBS):
        return ALLOWED_HUBS
    if size > 2 ** HUB_BITS // 3:
        raise ValueError(f"a whitelist of {size} does not fit scattered below 2**{HUB_BITS}")
    stride = 2 * size + 1
    hubs = tuple(sorted({1 + (index * stride) % (2**HUB_BITS - 1) for index in range(size)}))
    if len(hubs) != size:
        raise ValueError(
            f"a whitelist of {size} scattered by {stride} collapses to {len(hubs)} identifiers: "
            f"gcd({stride}, {2**HUB_BITS - 1}) is {math.gcd(stride, 2**HUB_BITS - 1)}, so the "
            "stride's orbit is shorter than the set. Pick another size"
        )
    return hubs

RECORDS_PER_VEHICLE_DEFAULT = 20

POSITIVE_LOAD_RATIO_NUMERATOR = 9
POSITIVE_LOAD_RATIO_DENOMINATOR = 10


RECORD_ID_BITS = 32
VEHICLE_ID_BITS = 32
TIME_BITS = 32
HUB_BITS = 16
LOAD_KG_BITS = 16

COUNT_BITS = 40

FIAT_SHAMIR_DOMAIN = b"zk-data-quality"


@dataclass(frozen=True, slots=True)
class Record:
    record_id: int
    active: bool
    vehicle_id: int
    start: int
    end: int
    origin_hub: int
    destination_hub: int
    load_kg: int

    def to_field_elements(self) -> tuple[int, ...]:
        return (
            self.record_id,
            int(self.active),
            self.vehicle_id,
            self.start,
            self.end,
            self.origin_hub,
            self.destination_hub,
            self.load_kg,
        )

    @classmethod
    def from_field_elements(cls, values) -> "Record":
        values = tuple(values)
        if len(values) != FIELDS_PER_RECORD:
            raise ValueError(f"expected {FIELDS_PER_RECORD} field elements, got {len(values)}")
        record_id, active, vehicle_id, start, end, origin_hub, destination_hub, load_kg = values
        return cls(
            record_id=record_id,
            active=bool(active),
            vehicle_id=vehicle_id,
            start=start,
            end=end,
            origin_hub=origin_hub,
            destination_hub=destination_hub,
            load_kg=load_kg,
        )

    def with_changes(self, **changes) -> "Record":
        return replace(self, **changes)


def sort_key_vehicle_start(record: Record) -> tuple[int, int, int]:
    return (int(not record.active), record.vehicle_id, record.start)


def sort_key_record_id(record: Record) -> tuple[int, int]:
    return (int(not record.active), record.record_id)


SORT_KEYS = {
    "key1": sort_key_vehicle_start,
    "key2": sort_key_record_id,
}


def composite_sort_key_vehicle_start(record: Record) -> int:
    return (record.vehicle_id << TIME_BITS) | record.start


def composite_sort_key_record_id(record: Record) -> int:
    return record.record_id


COMPOSITE_SORT_KEYS = {
    "key1": composite_sort_key_vehicle_start,
    "key2": composite_sort_key_record_id,
}

COMPOSITE_SORT_KEY_BITS = {
    "key1": VEHICLE_ID_BITS + TIME_BITS,
    "key2": RECORD_ID_BITS,
}


def sorted_permutation(records, sort_key: Callable[[Record], tuple]) -> tuple[int, ...]:
    return tuple(sorted(range(len(records)), key=lambda position: sort_key(records[position])))


@dataclass(frozen=True, slots=True)
class Dataset:

    variant: str
    record_count: int
    records_per_vehicle: int
    seed: int
    blinding_seed: int
    presented_records: tuple[Record, ...]
    permutation_to_key1: tuple[int, ...]
    permutation_to_key2: tuple[int, ...]
    target_predicate: str | None
    grand_product_blinding_element: int = 1
    allowed_hubs: tuple[int, ...] = ALLOWED_HUBS

    @property
    def row_count(self) -> int:
        return len(self.presented_records)

    def permutation(self, sort_key_name: str) -> tuple[int, ...]:
        if sort_key_name == "key1":
            return self.permutation_to_key1
        if sort_key_name == "key2":
            return self.permutation_to_key2
        raise KeyError(sort_key_name)

    def view(self, sort_key_name: str) -> tuple[Record, ...]:
        return tuple(self.presented_records[position] for position in self.permutation(sort_key_name))
