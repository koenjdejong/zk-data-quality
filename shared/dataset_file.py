import json
from pathlib import Path

from shared.schema import Dataset
from shared.reference import (
    challenges_for,
    fingerprint,
    grand_product,
    record_stride,
    transcript_commitment,
    traversals_of,
)
from shared.schema import (
    BN254_SCALAR_FIELD_MODULUS,
    ALLOWED_HUBS,
    COUNT_BITS,
    FIELD_NAMES,
    HUB_BITS,
    LOAD_KG_BITS,
    POSITIVE_LOAD_RATIO_DENOMINATOR,
    POSITIVE_LOAD_RATIO_NUMERATOR,
    RECORD_ID_BITS,
    TIME_BITS,
    TIME_MAXIMUM,
    TIME_MINIMUM,
    VEHICLE_ID_BITS,
    Record,
)

SCHEMA_VERSION = 4
DEFAULT_DIRECTORY = Path(__file__).resolve().parent.parent / "data"


def _hex(value: int) -> str:
    return f"0x{value % BN254_SCALAR_FIELD_MODULUS:064x}"


def filename(dataset: Dataset) -> str:
    return (
        f"{dataset.variant}"
        f"-n{dataset.record_count}"
        f"-perVehicle{dataset.records_per_vehicle}"
        f"-seed{dataset.seed}"
        f"-blinding{dataset.blinding_seed}"
        + (f"-hubs{len(dataset.allowed_hubs)}" if len(dataset.allowed_hubs) != len(ALLOWED_HUBS) else "")
        + ".json"
    )


def constants_document(allowed_hubs=ALLOWED_HUBS) -> dict:
    return {
        "time_minimum": TIME_MINIMUM,
        "time_maximum": TIME_MAXIMUM,
        "allowed_hubs": list(allowed_hubs),
        "positive_load_ratio_numerator": POSITIVE_LOAD_RATIO_NUMERATOR,
        "positive_load_ratio_denominator": POSITIVE_LOAD_RATIO_DENOMINATOR,
        "count_bits": COUNT_BITS,
        "range_check_bits": {
            "record_id": RECORD_ID_BITS,
            "vehicle_id": VEHICLE_ID_BITS,
            "start": TIME_BITS,
            "end": TIME_BITS,
            "origin_hub": HUB_BITS,
            "destination_hub": HUB_BITS,
            "load_kg": LOAD_KG_BITS,
        },
    }


def to_document(dataset: Dataset) -> dict:
    fingerprint_challenge, grand_product_challenge = challenges_for(dataset)
    return {
        "schema_version": SCHEMA_VERSION,
        "variant": dataset.variant,
        "record_count": dataset.record_count,
        "row_count": dataset.row_count,
        "records_per_vehicle": dataset.records_per_vehicle,
        "seed": dataset.seed,
        "blinding_seed": dataset.blinding_seed,
        "target_predicate": dataset.target_predicate,
        "field_names": list(FIELD_NAMES),
        "constants": constants_document(dataset.allowed_hubs),
        "presented_records": [
            [str(value) for value in record.to_field_elements()]
            for record in dataset.presented_records
        ],
        "blinding": {
            "grand_product_element": _hex(dataset.grand_product_blinding_element),
        },
        "permutation_to_key1": list(dataset.permutation_to_key1),
        "permutation_to_key2": list(dataset.permutation_to_key2),
        "transcript_commitment": _hex(transcript_commitment(traversals_of(dataset))),
        "challenges": {
            "fingerprint_challenge": _hex(fingerprint_challenge),
            "grand_product_challenge": _hex(grand_product_challenge),
            "record_stride": _hex(record_stride(fingerprint_challenge)),
        },
        "expected": {
            "fingerprint": _hex(fingerprint(dataset.presented_records, fingerprint_challenge)),
            "grand_product_presented": _hex(
                grand_product(
                    dataset.presented_records,
                    fingerprint_challenge,
                    grand_product_challenge,
                    dataset.grand_product_blinding_element,
                )
            ),
            "grand_product_key1": _hex(
                grand_product(
                    dataset.view("key1"),
                    fingerprint_challenge,
                    grand_product_challenge,
                    dataset.grand_product_blinding_element,
                )
            ),
            "grand_product_key2": _hex(
                grand_product(
                    dataset.view("key2"),
                    fingerprint_challenge,
                    grand_product_challenge,
                    dataset.grand_product_blinding_element,
                )
            ),
        },
    }


def from_document(document: dict) -> Dataset:
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version {document['schema_version']!r}, "
            f"this build reads {SCHEMA_VERSION}"
        )
    if tuple(document["field_names"]) != FIELD_NAMES:
        raise ValueError(
            f"field order changed: file has {document['field_names']}, schema has {list(FIELD_NAMES)}"
        )
    return Dataset(
        variant=document["variant"],
        record_count=document["record_count"],
        records_per_vehicle=document["records_per_vehicle"],
        seed=document["seed"],
        blinding_seed=document["blinding_seed"],
        presented_records=tuple(
            Record.from_field_elements(int(value) for value in values)
            for values in document["presented_records"]
        ),
        permutation_to_key1=tuple(document["permutation_to_key1"]),
        permutation_to_key2=tuple(document["permutation_to_key2"]),
        target_predicate=document["target_predicate"],
        allowed_hubs=tuple(document["constants"]["allowed_hubs"]),
        grand_product_blinding_element=int(document["blinding"]["grand_product_element"], 16),
    )


def write(dataset: Dataset, directory: Path = DEFAULT_DIRECTORY) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename(dataset)
    path.write_text(json.dumps(to_document(dataset), indent=1) + "\n")
    return path


def read(path: Path) -> Dataset:
    document = json.loads(Path(path).read_text())
    dataset = from_document(document)
    recomputed = to_document(dataset)
    for section in ("transcript_commitment", "challenges", "expected"):
        if recomputed[section] != document[section]:
            raise ValueError(f"{path}: {section} does not match the rows it claims to describe")
    return dataset
