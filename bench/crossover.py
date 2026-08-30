import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.backends import (
    add_output_argument,
    build_rust_backends,
    results_directory,
    run_backend,
    shown,
)
from shared import dataset_file, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED

UNITS = {
    "noir": ("acir_opcodes", "ultrahonk_gates"),
    "groth16": ("constraints",),
}


DEFAULT_REPETITIONS = 5


def measure(backend: str, path: Path, all_pairs: bool, repetitions: int = 1) -> dict:
    reports = [run_backend(backend, path, all_pairs=all_pairs) for _ in range(repetitions)]
    for unit in UNITS[backend]:
        distinct = {report.get(unit) for report in reports}
        if len(distinct) > 1:
            raise RuntimeError(
                f"{backend} reported {sorted(distinct)} for {unit} across {repetitions} runs of the "
                "same dataset; a constraint count is deterministic, so this is a harness fault"
            )
    summary = dict(reports[0])
    seconds = [sum(report["phases"].values()) for report in reports]
    peaks = [report["peak_rss_bytes"] for report in reports]
    summary["measured_seconds"] = seconds
    summary["seconds_median"] = statistics.median(seconds)
    summary["seconds_minimum"] = min(seconds)
    summary["seconds_maximum"] = max(seconds)
    summary["peak_rss_bytes"] = int(statistics.median(peaks))
    summary["repetitions"] = repetitions
    return summary


def warm_up(backend: str, path: Path) -> None:
    for all_pairs in (False, True):
        try:
            run_backend(backend, path, all_pairs=all_pairs)
        except Exception:
            pass


def crossover_of(measurements: list[dict], unit: str) -> str:
    previous = None
    for row in measurements:
        sorted_cost, all_pairs_cost = row["sorted"][unit], row["all_pairs"][unit]
        if sorted_cost is None or all_pairs_cost is None:
            continue
        if all_pairs_cost > sorted_cost:
            if previous is None:
                return f"below {row['record_count']}"
            return f"between {previous} and {row['record_count']}"
        previous = row["record_count"]
    return f"above {measurements[-1]['record_count']}"


def main() -> None:
    parser = argparse.ArgumentParser(prog="bench/crossover.py")
    parser.add_argument("--record-count", type=int, nargs="+", default=[5, 10, 20, 40, 80, 160])
    parser.add_argument("--records-per-vehicle", type=int, default=2)
    parser.add_argument("--backend", nargs="+", default=list(UNITS))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    parser.add_argument(
        "--repetitions",
        type=int,
        default=DEFAULT_REPETITIONS,
        help="timing samples per cell; reported as a median with the range",
    )
    parser.add_argument(
        "--output-name",
        default="crossover.json",
        help="the result file's name",
    )
    add_output_argument(parser)
    arguments = parser.parse_args()

    print("building the Rust backends...", file=sys.stderr)
    build_rust_backends()

    results = {}
    for backend in arguments.backend:
        units = UNITS[backend]
        print(f"\n{backend}")
        header = f"  {'records':>8}"
        for unit in units:
            header += f" {'sorted ' + unit:>26} {'all-pairs ' + unit:>26}"
        header += f" {'sorted s':>10} {'all-pairs s':>12}"
        print(header)

        measurements = []
        for record_count in arguments.record_count:
            dataset = generator.build(
                "honest",
                record_count,
                arguments.records_per_vehicle,
                arguments.seed,
                arguments.blinding_seed,
            )
            path = dataset_file.write(dataset)
            if not measurements:
                warm_up(backend, path)
            sorted_report = measure(backend, path, False, arguments.repetitions)
            all_pairs_report = measure(backend, path, True, arguments.repetitions)
            for report, label in ((sorted_report, "sorted"), (all_pairs_report, "all-pairs")):
                if not report["verified"]:
                    raise RuntimeError(
                        f"{backend} {label} did not verify the honest dataset at n={record_count}"
                    )

            row = {
                "record_count": record_count,
                "sorted": {unit: sorted_report.get(unit) for unit in units},
                "all_pairs": {unit: all_pairs_report.get(unit) for unit in units},
            }
            for form, report in (("sorted", sorted_report), ("all_pairs", all_pairs_report)):
                row[form]["seconds"] = round(report["seconds_median"], 6)
                row[form]["seconds_minimum"] = round(report["seconds_minimum"], 6)
                row[form]["seconds_maximum"] = round(report["seconds_maximum"], 6)
                row[form]["seconds_samples"] = [round(s, 6) for s in report["measured_seconds"]]
                row[form]["repetitions"] = report["repetitions"]
                row[form]["peak_rss_bytes"] = report["peak_rss_bytes"]
            measurements.append(row)

            line = f"  {record_count:>8}"
            for unit in units:
                line += f" {row['sorted'][unit]:>26} {row['all_pairs'][unit]:>26}"
            line += f" {row['sorted']['seconds']:>10.3f} {row['all_pairs']['seconds']:>12.3f}"
            print(line)

        results[backend] = measurements
        for unit in (*units, "seconds"):
            print(f"    crossover in {unit}: {crossover_of(measurements, unit)}")

    output = results_directory(arguments) / arguments.output_name
    output.write_text(
        json.dumps(
            {
                "records_per_vehicle": arguments.records_per_vehicle,
                "repetitions": arguments.repetitions,
                "seed": arguments.seed,
                "blinding_seed": arguments.blinding_seed,
                "backends": results,
                "crossovers": {
                    backend: {
                        unit: crossover_of(measurements, unit)
                        for unit in (*UNITS[backend], "seconds")
                    }
                    for backend, measurements in results.items()
                },
                "folding": (
                    "not applicable: a folded step carries a fixed number of field elements, so an "
                    "all-pairs check would need arity linear in the record count and the steps "
                    "would stop being identical. See nova/tests/inexpressible.rs."
                ),
            },
            indent=1,
        )
        + "\n"
    )
    print(f"\nwritten to {shown(output)}")


if __name__ == "__main__":
    main()
