import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.backends import BACKEND_NAMES, build_rust_backends, run_backend
from bench.backends import add_output_argument, results_directory, shown
from shared import dataset_file, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED


def measure(backend: str, path: Path, repetitions: int) -> dict:
    reports = [run_backend(backend, path) for _ in range(repetitions)]
    assert all(report["verified"] for report in reports), f"{backend} did not verify {path.name}"
    proving_phases = [
        phase for phase in reports[0]["phases"] if phase not in ("verify", "synthesis")
    ]
    return {
        "verify_seconds": statistics.median(report["phases"]["verify"] for report in reports),
        "verify_minimum": min(report["phases"]["verify"] for report in reports),
        "verify_maximum": max(report["phases"]["verify"] for report in reports),
        "prove_seconds": statistics.median(
            sum(report["phases"][phase] for phase in proving_phases) for report in reports
        ),
        "proof_bytes": reports[0]["proof_bytes"],
        "peak_rss_bytes": max(report["peak_rss_bytes"] for report in reports),
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="bench/verification.py")
    parser.add_argument("--record-count", type=int, nargs="+", default=[10, 40, 100, 200, 400])
    parser.add_argument("--records-per-vehicle", type=int, default=2)
    parser.add_argument("--backend", nargs="+", default=list(BACKEND_NAMES))
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    add_output_argument(parser)
    arguments = parser.parse_args()

    print("building the Rust backends...", file=sys.stderr)
    build_rust_backends()

    measurements = []
    for backend in arguments.backend:
        print(f"\n{backend}")
        print(f"  {'records':>8} {'prove s':>10} {'verify s':>10} "
              f"{'verify min-max':>20} {'proof B':>9} {'peak GB':>9}")
        for record_count in arguments.record_count:
            dataset = generator.build(
                "honest",
                record_count,
                arguments.records_per_vehicle,
                arguments.seed,
                arguments.blinding_seed,
            )
            path = dataset_file.write(dataset)
            result = measure(backend, path, arguments.repetitions)
            measurements.append({"backend": backend, "record_count": record_count, **result})
            span = f"{result['verify_minimum']:.4f}-{result['verify_maximum']:.4f}"
            print(
                f"  {record_count:>8} {result['prove_seconds']:>10.3f} "
                f"{result['verify_seconds']:>10.4f} {span:>20} {result['proof_bytes']:>9} "
                f"{result['peak_rss_bytes'] / 1024**3:>9.3f}"
            )

    print("\nShape of each curve, smallest to largest record count:")
    for backend in arguments.backend:
        rows = [row for row in measurements if row["backend"] == backend]
        proving_growth = rows[-1]["prove_seconds"] / max(rows[0]["prove_seconds"], 1e-9)
        verify_growth = rows[-1]["verify_seconds"] / max(rows[0]["verify_seconds"], 1e-9)
        record_growth = rows[-1]["record_count"] / rows[0]["record_count"]
        sizes = {row["proof_bytes"] for row in rows}
        print(
            f"  {backend:<10} records x{record_growth:<6.0f} "
            f"prove x{proving_growth:<7.1f} verify x{verify_growth:<7.2f} "
            f"proof size {'flat' if len(sizes) == 1 else 'varies: ' + str(sorted(sizes))}"
        )

    output = results_directory(arguments) / "verification-cost.json"
    output.write_text(json.dumps(measurements, indent=1) + "\n")
    print(f"\nwritten to {shown(output)}")


if __name__ == "__main__":
    main()
