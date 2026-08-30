import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.backends import BACKEND_NAMES, ROOT, build_rust_backends, run_backend
from bench.backends import add_output_argument, results_directory, shown
from shared import dataset_file, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED


FIELD_COMPARISONS = {
    "in_circuit": {"fingerprint_against_the_opening": 1, "commitment_against_the_published": 1},
    "between_proofs": {
        "fingerprint_against_the_opening": 1,
        "commitment_against_the_published": 1,
        "grand_product_equalities": 2,
    },
}


def measure(backend: str, path: Path, repetitions: int) -> dict:
    runs = []
    for _ in range(repetitions):
        report = run_backend(backend, path)
        if not report["verified"]:
            raise RuntimeError(f"{backend} did not verify {path.name}")
        runs.append(report)
    verify_seconds = [report["phases"]["verify"] for report in runs]
    latest = runs[-1]
    separate_traversals = latest.get("sorted_folds", [])
    proofs = 1 + len(separate_traversals)
    return {
        "proofs_per_party": proofs,
        "proof_bytes_per_party": latest["proof_bytes"],
        "verify_seconds_per_party": round(statistics.median(verify_seconds), 6),
        "verify_seconds_minimum": round(min(verify_seconds), 6),
        "verify_seconds_maximum": round(max(verify_seconds), 6),
        "link_location": "between_proofs" if separate_traversals else "in_circuit",
    }


def hyperkzg_available() -> tuple[bool, str]:
    completed = subprocess.run(
        ["cargo", "build", "--release", "-p", "nova", "--features", "hyperkzg"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["cargo", "build", "--release", "-p", "nova"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return False, f"the feature does not build: {completed.stderr.strip().splitlines()[-1][:160]}"
    return False, (
        "the feature builds, but nova-snark's HyperKZG commitment key requires a powers-of-tau file "
        "from a trusted setup ceremony; the in-repository fallback is explicitly insecure, so no "
        "number is reported for it"
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="bench/audit.py")
    parser.add_argument("--record-count", type=int, default=2000)
    parser.add_argument(
        "--parties",
        type=int,
        default=5,
        help="parties in a round; the motivating deployment has five to seven",
    )
    parser.add_argument("--records-per-vehicle", type=int, default=20)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--backend", nargs="+", default=list(BACKEND_NAMES))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    add_output_argument(parser)
    arguments = parser.parse_args()

    print("building the Rust backends...", file=sys.stderr)
    build_rust_backends()

    dataset = generator.build(
        "honest",
        arguments.record_count,
        arguments.records_per_vehicle,
        arguments.seed,
        arguments.blinding_seed,
    )
    path = dataset_file.write(dataset)

    findings = {}
    for backend in arguments.backend:
        per_party = measure(backend, path, arguments.repetitions)
        comparisons = FIELD_COMPARISONS[per_party["link_location"]]
        findings[backend] = {
            **per_party,
            "round": {
                "parties": arguments.parties,
                "proofs": per_party["proofs_per_party"] * arguments.parties,
                "bytes": per_party["proof_bytes_per_party"] * arguments.parties,
                "verify_seconds": round(
                    per_party["verify_seconds_per_party"] * arguments.parties, 6
                ),
                "field_comparisons": {
                    name: count * arguments.parties for name, count in comparisons.items()
                },
            },
        }

    available, reason = hyperkzg_available()

    print(
        f"\nauditing one completed round: {arguments.parties} parties, "
        f"{arguments.record_count} records each, no participation\n"
    )
    print(f"{'backend':<10} {'proofs':>7} {'transferred':>13} {'verified in':>13}  what else the auditor checks")
    print("-" * 104)
    for backend, finding in findings.items():
        round_cost = finding["round"]
        comparisons = ", ".join(
            f"{count} {name.replace('_', ' ')}" for name, count in round_cost["field_comparisons"].items()
        )
        print(
            f"{backend:<10} {round_cost['proofs']:>7} "
            f"{round_cost['bytes'] / 1024:>10.1f} kB "
            f"{round_cost['verify_seconds'] * 1000:>10.1f} ms  {comparisons}"
        )

    print(
        "\nProof size is flat in the record count, so these figures hold at any dataset size;"
        "\nbench/verification.py is what establishes that."
    )
    print(f"\nHyperKZG: not measured — {reason}")

    output = results_directory(arguments) / "audit-cost.json"
    output.write_text(
        json.dumps(
            {
                "parties": arguments.parties,
                "record_count": arguments.record_count,
                "repetitions": arguments.repetitions,
                "polynomial_commitment": {
                    "measured": "ipa (transparent)",
                },
                "backends": findings,
            },
            indent=1,
        )
        + "\n"
    )
    print(f"\nwritten to {shown(output)}")


if __name__ == "__main__":
    main()
