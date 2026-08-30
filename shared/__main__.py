import argparse

from shared import dataset_file, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED
from shared.reference import failing_checks
from shared.schema import RECORDS_PER_VEHICLE_DEFAULT


def main() -> None:
    parser = argparse.ArgumentParser(prog="shared")
    parser.add_argument("--record-count", type=int, required=True)
    parser.add_argument(
        "--variant", nargs="+", default=["honest"], help="variant names, or 'all'"
    )
    parser.add_argument(
        "--records-per-vehicle", type=int, nargs="+", default=[RECORDS_PER_VEHICLE_DEFAULT]
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    arguments = parser.parse_args()

    requested = (
        list(generator.VARIANTS) if arguments.variant == ["all"] else arguments.variant
    )
    for records_per_vehicle in arguments.records_per_vehicle:
        for variant_name in requested:
            try:
                dataset = generator.build(
                    variant_name,
                    arguments.record_count,
                    records_per_vehicle,
                    arguments.seed,
                    arguments.blinding_seed,
                )
            except ValueError as unsupported:
                print(f"skipped {variant_name}: {unsupported}")
                continue
            path = dataset_file.write(dataset)
            failing = sorted(failing_checks(dataset))
            print(f"{path.name}  failing={failing or 'none'}")


if __name__ == "__main__":
    main()
