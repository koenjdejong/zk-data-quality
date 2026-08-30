import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.backends import (
    BACKEND_NAMES,
    DEFAULT_MEMORY_BUDGET_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    MEMBERSHIP_GADGETS,
    build_rust_backends,
    gadget_for,
    run_backend,
)
from shared import dataset_file, reference, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED
from shared.schema import RECORDS_PER_VEHICLE_DEFAULT

CONSTRAINT_FIELDS = ("constraints", "step_constraints", "acir_opcodes", "ultrahonk_gates")


def check(dataset, report: dict) -> list[str]:
    problems = []
    broken = sorted(reference.failing_checks(dataset))
    expected = not broken

    if report["verified"] != expected:
        problems.append(
            f"verified={report['verified']} but the reference's failing checks are "
            f"{', '.join(broken) or 'none'}"
        )
    if report["satisfied"] != report["verified"]:
        problems.append(
            f"satisfied={report['satisfied']} but verified={report['verified']}; with the link "
            f"enforced in-circuit these must agree"
        )
    anchor = report.get("anchor_fold", report)
    if anchor["verified"]:
        if int(report["commitment"], 16) == 0:
            problems.append("opened a zero commitment")
        if int(report["commitment"], 16) != int(report["published_commitment"], 16):
            problems.append(
                f"opened commitment {report['commitment']} but published "
                f"{report['published_commitment']}"
            )
        if int(report["fingerprint"], 16) != int(report["expected_fingerprint"], 16):
            problems.append(
                f"folded fingerprint {report['fingerprint']} but the reference is "
                f"{report['expected_fingerprint']}"
            )
    elif int(report["commitment"], 16) != 0 or int(report["fingerprint"], 16) != 0:
        problems.append("reported a binding quantity without a verified anchor fold")
    return problems


def describe_constraints(report: dict) -> str:
    counts = [
        f"{field}={report[field]}" for field in CONSTRAINT_FIELDS if report.get(field) is not None
    ]
    return " ".join(counts)


def main() -> None:
    parser = argparse.ArgumentParser(prog="bench/run.py")
    parser.add_argument("--record-count", type=int, required=True)
    parser.add_argument("--variant", nargs="+", default=["honest"], help="variant names, or 'all'")
    parser.add_argument(
        "--records-per-vehicle", type=int, default=RECORDS_PER_VEHICLE_DEFAULT
    )
    parser.add_argument("--backend", nargs="+", default=list(BACKEND_NAMES))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    parser.add_argument(
        "--memory-budget-gb",
        type=float,
        default=DEFAULT_MEMORY_BUDGET_BYTES / 1024**3,
        help="a run whose peak resident set exceeds this is killed and reported as infeasible",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--membership-gadget",
        choices=MEMBERSHIP_GADGETS,
        default=None,
        help="which shape of P3's set-membership gadget Noir should compile",
    )
    arguments = parser.parse_args()

    requested = list(generator.VARIANTS) if arguments.variant == ["all"] else arguments.variant

    print("building the Rust backends...", file=sys.stderr)
    build_rust_backends()

    failures = 0
    print(
        f"guard: peak RSS <= {arguments.memory_budget_gb:.0f} GB, wall clock <= "
        f"{arguments.timeout:.0f}s\n"
        + (
            f"noir's P3 gadget: {arguments.membership_gadget}\n"
            if arguments.membership_gadget
            else ""
        )
    )
    for variant_name in requested:
        try:
            dataset = generator.build(
                variant_name,
                arguments.record_count,
                arguments.records_per_vehicle,
                arguments.seed,
                arguments.blinding_seed,
            )
        except ValueError as unsupported:
            print(f"{variant_name:<16} skipped: {unsupported}")
            continue
        path = dataset_file.write(dataset)
        broken = sorted(reference.failing_checks(dataset))
        note = f"  (reference: {', '.join(broken)} fails)" if broken else ""
        print(f"{variant_name:<16} rows={dataset.row_count} expect verified={not broken}{note}")

        for backend in arguments.backend:
            report = run_backend(
                backend,
                path,
                timeout=arguments.timeout,
                memory_budget_bytes=int(arguments.memory_budget_gb * 1024**3),
                membership_gadget=gadget_for(backend, arguments.membership_gadget),
            )
            problems = check(dataset, report)
            status = "ok" if not problems else "FAILED"
            total = sum(report["phases"].values())
            print(
                f"  {backend:<10} satisfied={str(report['satisfied']):<5} "
                f"verified={str(report['verified']):<5} {total:7.3f}s "
                f"proof={report['proof_bytes']:>7}B  peak={report['peak_rss_bytes'] / 1024**3:5.2f}GB  "
                f"{describe_constraints(report)}  {status}"
            )
            for problem in problems:
                print(f"    {backend}: {problem}")
                failures += 1
        print()

    if failures:
        print(f"RESULT: {failures} disagreement(s) with the reference")
        sys.exit(1)
    print("RESULT: every backend agrees with the reference")
    print(
        "The fingerprint is the one quantity comparable across backends, and every backend that\n"
        "produced a proof folded the same value as shared/reference.py."
    )


if __name__ == "__main__":
    main()
