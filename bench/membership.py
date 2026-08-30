import argparse
import json
import statistics
import sys
from pathlib import Path

CONSTRAINT_FIELDS = ("constraints", "step_constraints", "acir_opcodes", "ultrahonk_gates")


def counts_agree(reports: list[dict], label: str) -> dict:
    measured = [
        {field: report[field] for field in CONSTRAINT_FIELDS if report.get(field) is not None}
        for report in reports
    ]
    if any(count != measured[0] for count in measured[1:]):
        raise RuntimeError(
            f"{label} reported differing constraint counts across {len(reports)} runs of the same "
            f"dataset ({measured}); a constraint count is deterministic, so this is a harness fault"
        )
    return measured[0]


def summarise_seconds(reports: list[dict]) -> dict:
    seconds = [sum(report["phases"].values()) for report in reports]
    peaks = [report["peak_rss_bytes"] for report in reports]
    return {
        "seconds": round(statistics.median(seconds), 3),
        "seconds_minimum": round(min(seconds), 3),
        "seconds_maximum": round(max(seconds), 3),
        "seconds_samples": [round(value, 3) for value in seconds],
        "repetitions": len(reports),
        "phases_median_seconds": {
            phase: round(
                statistics.median([report["phases"].get(phase, 0.0) for report in reports]), 3
            )
            for phase in reports[0]["phases"]
        },
        "peak_rss_bytes": int(statistics.median(peaks)),
    }


def unit_of(measured: dict) -> str | None:
    return next((field for field in CONSTRAINT_FIELDS if field in measured), None)


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.backends import (
    DEFAULT_MEMORY_BUDGET_BYTES,
    MEMBERSHIP_GADGETS,
    build_rust_backends,
    gadget_for,
    probe_backend,
    run_backend,
)
from bench.backends import add_output_argument, write
from shared import dataset_file, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED
from shared.schema import scattered_hub_whitelist

SIZES = [8, 64, 512, 4096]

EXTENDED_SIZES = [8192, 16384]

REFERENCE_BACKENDS = ["groth16", "nova"]

DEFAULT_REPETITIONS = 5

DEFAULT_HEADROOM_FRACTION = 0.5

QUERIES_PER_ROW = 2


def hubs_for(size: int) -> tuple[int, ...]:
    return scattered_hub_whitelist(size)


def dataset_for(size: int, arguments, variant: str = "honest") -> Path:
    return dataset_file.write(
        generator.build(
            variant,
            arguments.record_count,
            arguments.records_per_vehicle,
            arguments.seed,
            arguments.blinding_seed,
            allowed_hubs=hubs_for(size),
        )
    )


def measure(backend: str, path: Path, gadget: str | None, repetitions: int) -> dict:
    reports = [
        run_backend(backend, path, membership_gadget=gadget_for(backend, gadget))
        for _ in range(repetitions)
    ]
    if not all(report["verified"] for report in reports):
        return {"error": "did not verify"}
    if backend == "noir":
        compiled = {report.get("membership_gadget") for report in reports}
        if compiled != {gadget}:
            raise RuntimeError(
                f"asked noir for the {gadget!r} gadget and it reported {compiled}; the driver and "
                "this harness disagree about what was measured"
            )
    return {**counts_agree(reports, backend), **summarise_seconds(reports)}


def probe(backend: str, path: Path, gadget: str | None) -> dict:
    outcome = probe_backend(backend, path, membership_gadget=gadget_for(backend, gadget))
    cell = {
        "measured": False,
        "elapsed_seconds": round(outcome["elapsed_seconds"], 3),
        "peak_rss_bytes": outcome["peak_rss_bytes"],
    }
    if outcome["killed"]:
        return {**cell, "cap": "guard", "cap_detail": outcome["killed"]}
    if "report" not in outcome:
        error = outcome["error"]
        detail = "bb-write-vk" if "write_vk" in error else "compile" if "compile" in error else None
        return {**cell, "cap": "toolchain", "cap_detail": detail, "error": error}
    report = outcome["report"]
    return {
        "measured": True,
        **{field: report[field] for field in ("acir_opcodes", "ultrahonk_gates")},
        "seconds": round(sum(report["phases"].values()), 3),
        "peak_rss_bytes": outcome["peak_rss_bytes"],
        "repetitions": 1,
    }


def per_member(cell: dict, size: int, floor: dict | None, row_count: int) -> dict:
    if floor is None or size == floor["size"] or "error" in cell or not cell.get("measured", True):
        return {}
    queries = QUERIES_PER_ROW * row_count
    names = {
        "acir_opcodes": "opcodes",
        "ultrahonk_gates": "gates",
        "constraints": "constraints",
        "step_constraints": "step_constraints",
    }
    derived = {}
    for field, name in names.items():
        if cell.get(field) is None or floor["cell"].get(field) is None:
            continue
        slope = (cell[field] - floor["cell"][field]) / (size - floor["size"])
        derived[f"{name}_per_member"] = round(slope, 3)
        derived[f"{name}_per_query_member"] = round(slope / queries, 4)
    return derived


def sweep_gadget(gadget: str, arguments, budget: float) -> dict:
    series, floor, stopped = [], None, False
    for size in arguments.sizes + arguments.extended_sizes:
        path = dataset_for(size, arguments)
        if stopped:
            cell = probe("noir", path, gadget)
        else:
            cell = measure("noir", path, gadget, arguments.repetitions)
            cell["measured"] = True
            if floor is None and "error" not in cell:
                floor = {"size": size, "cell": cell}
            if cell.get("peak_rss_bytes", 0) > budget:
                stopped = True
        cell.update(per_member(cell, size, floor, arguments.record_count + 1))
        series.append({"whitelist_size": size, **cell})
        print(f"  |S| = {size:<6} {gadget:<9} {summarise(cell)}", flush=True)
    return {"gadget": gadget, "measurements": series}


def summarise(cell: dict) -> str:
    if "error" in cell and "cap" not in cell:
        return cell["error"]
    if cell.get("cap"):
        return f"CAP ({cell['cap']}: {cell.get('cap_detail')}) after {cell['elapsed_seconds']:.0f}s"
    unit = unit_of(cell)
    memory = f" / {cell['peak_rss_bytes'] / 1024**3:.2f} GB" if cell.get("peak_rss_bytes") else ""
    return f"{cell[unit]} {unit} / {cell['seconds']:.2f}s{memory}" if unit else f"{cell['seconds']}s"


def equivalence(arguments) -> dict:
    expectations = {"honest": True, "bad_hub": False, "laundered": True}
    findings, published = {}, {}
    for gadget in arguments.gadget:
        findings[gadget] = {}
        for variant, expected in expectations.items():
            path = dataset_for(arguments.sizes[0], arguments, variant)
            outcome = probe_backend("noir", path, membership_gadget=gadget)
            report = outcome.get("report", {})
            verified = bool(report.get("verified"))
            findings[gadget][variant] = {
                "verified": verified,
                "expected": expected,
                "agrees": verified == expected,
            }
            if variant == "honest":
                published[gadget] = {
                    "commitment": report.get("commitment"),
                    "fingerprint": report.get("fingerprint"),
                }
    identical = len({json.dumps(value, sort_keys=True) for value in published.values()}) == 1
    return {
        "variants": findings,
        "published_values_are_identical_across_gadgets": identical,
        "published_values": published,
        "holds": identical
        and all(case["agrees"] for gadget in findings.values() for case in gadget.values()),
    }






def coordinates(document: dict) -> None:
    print("\npgfplots coordinates (n = %d):" % document["record_count"])
    for unit in ("ultrahonk_gates", "seconds"):
        print(f"\n  % {unit}")
        for series in document["gadgets"]:
            points = " ".join(
                f"({cell['whitelist_size']},{cell[unit]})"
                for cell in series["measurements"]
                if cell.get("measured") and cell.get(unit) is not None
            )
            print(f"  \\addplot coordinates {{{points}}};  % {series['gadget']}")
        for series in document.get("reference", []):
            unit_name = unit if unit == "seconds" else unit_of(series["measurements"][0])
            points = " ".join(
                f"({cell['whitelist_size']},{cell[unit_name]})"
                for cell in series["measurements"]
                if cell.get(unit_name) is not None
            )
            print(f"  % {series['backend']} ({unit_name}): {points}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="bench/membership.py")
    parser.add_argument("--record-count", type=int, default=200)
    parser.add_argument("--records-per-vehicle", type=int, default=20)
    parser.add_argument("--sizes", nargs="+", type=int, default=list(SIZES))
    parser.add_argument("--extended-sizes", nargs="*", type=int, default=list(EXTENDED_SIZES))
    parser.add_argument("--gadget", nargs="+", choices=MEMBERSHIP_GADGETS, default=list(MEMBERSHIP_GADGETS))
    parser.add_argument("--reference-backend", nargs="*", default=list(REFERENCE_BACKENDS))
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    parser.add_argument("--memory-headroom-fraction", type=float, default=DEFAULT_HEADROOM_FRACTION)
    parser.add_argument("--output-name", default="set-membership.json")
    parser.add_argument("--skip-equivalence", action="store_true")
    add_output_argument(parser)
    arguments = parser.parse_args()

    budget = arguments.memory_headroom_fraction * DEFAULT_MEMORY_BUDGET_BYTES
    if arguments.reference_backend:
        print("building the Rust backends...", file=sys.stderr)
        build_rust_backends()

    warming = dataset_for(arguments.sizes[0], arguments)
    print("warming up each backend and gadget (one discarded run)...", file=sys.stderr)
    for gadget in arguments.gadget:
        try:
            run_backend("noir", warming, membership_gadget=gadget)
        except Exception:
            pass
    for backend in arguments.reference_backend:
        try:
            run_backend(backend, warming)
        except Exception:
            pass

    print(
        f"\nwall clock is the median of {arguments.repetitions} runs, every phase included\n"
        f"\nP3's membership gadget against |S|, {arguments.record_count} records:"
    )
    gadgets = [sweep_gadget(gadget, arguments, budget) for gadget in arguments.gadget]

    reference = []
    for backend in arguments.reference_backend:
        print(f"\n{backend} (product of differences only):")
        series = []
        for size in arguments.sizes:
            cell = measure(backend, dataset_for(size, arguments), None, arguments.repetitions)
            cell["measured"] = "error" not in cell
            floor = {"size": arguments.sizes[0], "cell": series[0]} if series else None
            cell.update(per_member(cell, size, floor, arguments.record_count + 1))
            series.append({"whitelist_size": size, **cell})
            print(f"  |S| = {size:<6} {summarise(cell)}", flush=True)
        reference.append({"backend": backend, "measurements": series})

    checks = {}
    if not arguments.skip_equivalence:
        print("\nsemantic equivalence of the three shapes:")
        checks["equivalence"] = equivalence(arguments)
        print(f"  holds: {checks['equivalence']['holds']}")

    document = {
        "record_count": arguments.record_count,
        "row_count": arguments.record_count + 1,
        "queries_per_proof": QUERIES_PER_ROW * (arguments.record_count + 1),
        "records_per_vehicle": arguments.records_per_vehicle,
        "sizes": arguments.sizes,
        "extended_sizes": arguments.extended_sizes,
        "repetitions": arguments.repetitions,
        "seed": arguments.seed,
        "blinding_seed": arguments.blinding_seed,
        "memory_headroom_fraction": arguments.memory_headroom_fraction,
        "gadgets": gadgets,
        "reference": reference,
        "checks": checks,
    }
    write(arguments, arguments.output_name, document)
    coordinates(document)

    if not checks.get("equivalence", {"holds": True})["holds"]:
        print("\nthe three gadgets do not agree on the statement they prove", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
