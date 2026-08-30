import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.backends import (
    BACKEND_NAMES,
    DEFAULT_MEMORY_BUDGET_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    add_output_argument,
    build_rust_backends,
    probe_backend,
    results_directory,
)
from bench.backends import shown as shown_path
from shared import dataset_file, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED


def dataset_for(record_count: int, arguments) -> Path:
    return dataset_file.write(
        generator.build(
            "honest",
            record_count,
            arguments.records_per_vehicle,
            arguments.seed,
            arguments.blinding_seed,
        )
    )


_MEMORY_WORDS = (
    "out of memory",
    "oom",
    "bad_alloc",
    "cannot allocate",
    "failed to allocate",
    "allocation failed",
    "memory allocation",
    "sigkill",
    "signal: 9",
    "killed: 9",
    "exit -9",
    "exit -6",
    "exit -11",
)


def _memory_claim_disagreement(
    error: str, peak_rss_bytes: int, memory_budget_bytes: int
) -> dict | None:
    lowered = error.lower()
    matched = [word for word in _MEMORY_WORDS if word in lowered]
    if not matched or peak_rss_bytes > memory_budget_bytes:
        return None
    return {
        "error_blames_memory_on": matched,
        "peak_rss_gigabytes": round(peak_rss_bytes / 1024**3, 3),
        "memory_budget_gigabytes": round(memory_budget_bytes / 1024**3, 3),
        "resolved": False,
    }


def probe(backend: str, record_count: int, arguments) -> dict:
    memory_budget_bytes = int(arguments.memory_budget_gb * 1024**3)
    outcome = probe_backend(
        backend,
        dataset_for(record_count, arguments),
        timeout=arguments.timeout,
        memory_budget_bytes=memory_budget_bytes,
    )
    feasible = outcome["killed"] is None and "report" in outcome
    summary = {
        "record_count": record_count,
        "feasible": feasible,
        "killed": outcome["killed"],
        "limited_by": None if feasible else (outcome["killed"] or "toolchain"),
        "elapsed_seconds": round(outcome["elapsed_seconds"], 3),
        "peak_rss_gigabytes": round(outcome["peak_rss_bytes"] / 1024**3, 3),
    }
    if summary["limited_by"] == "toolchain":
        summary["error"] = outcome.get("error", "no report")
        disagreement = _memory_claim_disagreement(
            summary["error"], outcome["peak_rss_bytes"], memory_budget_bytes
        )
        if disagreement is not None:
            summary["memory_claim_disagreement"] = disagreement
            print(f"    NOTE: {disagreement['note']}", flush=True)
    print(
        f"    n={record_count:<8} {'ok' if feasible else 'FAILED':<7} "
        f"{summary['elapsed_seconds']:>8.1f}s  {summary['peak_rss_gigabytes']:>6.2f} GB"
        + (f"  limited by {summary['limited_by']}" if not feasible else "")
        + (f": {summary['error'].splitlines()[-1][:60]}" if "error" in summary else ""),
        flush=True,
    )
    return summary


def find_ceiling(backend: str, arguments) -> dict:
    probes = []

    highest_feasible = None
    lowest_infeasible = None
    record_count = arguments.start
    while record_count <= arguments.maximum:
        result = probe(backend, record_count, arguments)
        probes.append(result)
        if not result["feasible"]:
            lowest_infeasible = record_count
            break
        highest_feasible = record_count
        record_count *= 2

    if highest_feasible is None:
        return {
            "ceiling": None,
            "probes": probes,
        }
    if lowest_infeasible is None:
        return {
            "ceiling": None,
            "at_least": highest_feasible,
            "probes": probes,
        }

    resolution = max(arguments.resolution, highest_feasible * arguments.resolution_percent // 100, 1)
    while lowest_infeasible - highest_feasible > resolution:
        middle = (highest_feasible + lowest_infeasible) // 2
        result = probe(backend, middle, arguments)
        probes.append(result)
        if result["feasible"]:
            highest_feasible = middle
            resolution = max(
                arguments.resolution,
                highest_feasible * arguments.resolution_percent // 100,
                1,
            )
        else:
            lowest_infeasible = middle

    limited_by = next(
        (
            probe["limited_by"]
            for probe in probes
            if probe["record_count"] == lowest_infeasible and not probe["feasible"]
        ),
        None,
    )
    return {
        "ceiling": highest_feasible,
        "first_infeasible": lowest_infeasible,
        "limited_by": limited_by,
        "resolution": resolution,
        "probes": probes,
    }


def diagnose(probes: list[dict]) -> dict:
    successful = [probe for probe in probes if probe["feasible"]]
    if len(successful) < 3:
        return {"peak_rss_saturated": False}

    saturated_from = None
    for earlier, later in zip(successful, successful[1:]):
        if later["peak_rss_gigabytes"] < earlier["peak_rss_gigabytes"]:
            saturated_from = earlier["record_count"]
            break

    growth = []
    for earlier, later in zip(successful, successful[1:]):
        if earlier["elapsed_seconds"] > 0 and later["record_count"] > earlier["record_count"]:
            size_ratio = later["record_count"] / earlier["record_count"]
            time_ratio = later["elapsed_seconds"] / earlier["elapsed_seconds"]
            growth.append(
                {
                    "from": earlier["record_count"],
                    "to": later["record_count"],
                    "size_ratio": round(size_ratio, 2),
                    "time_ratio": round(time_ratio, 2),
                    "superlinear": time_ratio > size_ratio * 1.3,
                }
            )

    diagnosis = {
        "peak_rss_saturated": saturated_from is not None,
        "time_growth": growth,
    }
    if saturated_from is not None:
        diagnosis["saturated_from_record_count"] = saturated_from
        diagnosis["note"] = (
            f"peak resident set stopped increasing above n={saturated_from}, so every reading above "
            f"it understates demand and the memory budget cannot bind; the clock is what detects "
            f"infeasibility here"
        )
    return diagnosis


def confirm(backend: str, ceiling: int, arguments) -> dict:
    attempts = []
    candidate = ceiling
    for _ in range(arguments.confirmation_attempts):
        measured = measure_below(backend, candidate, arguments)
        attempts.append({"record_count": candidate, "held": "error" not in measured})
        if "error" not in measured:
            return {"confirmed": candidate, "attempts": attempts, "measured": measured}
        candidate -= max(arguments.resolution, candidate // 100, 1)
        if candidate <= 0:
            break
    return {"confirmed": None, "attempts": attempts}


def measure_below(backend: str, record_count: int, arguments) -> dict:
    path = dataset_for(record_count, arguments)
    runs = []
    for _ in range(arguments.repetitions):
        outcome = probe_backend(
            backend,
            path,
            timeout=arguments.timeout,
            memory_budget_bytes=int(arguments.memory_budget_gb * 1024**3),
        )
        if outcome["killed"] or "report" not in outcome:
            return {"record_count": record_count, "error": "became infeasible while repeating"}
        runs.append(outcome)
    seconds = [run["elapsed_seconds"] for run in runs]
    peaks = [run["peak_rss_bytes"] / 1024**3 for run in runs]
    return {
        "record_count": record_count,
        "repetitions": arguments.repetitions,
        "seconds_median": round(statistics.median(seconds), 3),
        "seconds_minimum": round(min(seconds), 3),
        "seconds_maximum": round(max(seconds), 3),
        "peak_rss_gigabytes_median": round(statistics.median(peaks), 3),
        "peak_rss_gigabytes_minimum": round(min(peaks), 3),
        "peak_rss_gigabytes_maximum": round(max(peaks), 3),
    }


def reanalyse(arguments) -> None:
    output = results_directory(arguments) / "ceilings.json"
    document = json.loads(output.read_text())
    for backend, finding in document["backends"].items():
        finding["diagnosis"] = diagnose(finding.get("probes", []))
        print(f"{backend}:")
        for entry in finding["diagnosis"].get("time_growth", []):
            marker = "  <-- superlinear" if entry["superlinear"] else ""
            print(
                f"    n {entry['from']:>6} -> {entry['to']:<6} "
                f"{entry['size_ratio']:.1f}x the work, {entry['time_ratio']:.1f}x the time{marker}"
            )
        if finding["diagnosis"]["peak_rss_saturated"]:
            print(f"    NOTE: {finding['diagnosis']['note']}")
        else:
            print("    peak resident set tracked demand throughout")
    output.write_text(json.dumps(document, indent=1) + "\n")
    print(f"\nrewritten {shown_path(output)}")


MERGEABLE_PARAMETERS = (
    "memory_budget_gigabytes",
    "timeout_seconds",
    "records_per_vehicle",
    "search_maximum",
    "seed",
    "blinding_seed",
)


def merge_with_the_previous_run(document: dict, output) -> dict:
    document["backends_measured_in_this_run"] = sorted(document["backends"])
    if not output.exists():
        return document
    try:
        previous = json.loads(output.read_text())
    except (OSError, ValueError):
        return document

    differing = [
        name
        for name in MERGEABLE_PARAMETERS
        if name in previous and previous[name] != document[name]
    ]
    if differing:
        document["replaced_the_previous_file_because"] = (
            "it was measured under different parameters (" + ", ".join(differing) + "), so its "
            "findings are a different measurement rather than the same one at a different time"
        )
        return document

    carried = []
    for backend, finding in previous.get("backends", {}).items():
        if backend in document["backends"]:
            continue
        finding["carried_forward"] = (
            "not measured in this run; the parameters are identical and nothing in this change "
            "affects this backend"
        )
        document["backends"][backend] = finding
        carried.append(backend)
    if carried:
        document["backends_carried_forward"] = sorted(carried)
    return document


def main() -> None:
    parser = argparse.ArgumentParser(prog="bench/ceiling.py")
    parser.add_argument("--backend", nargs="+", default=list(BACKEND_NAMES))
    parser.add_argument(
        "--memory-budget-gb", type=float, default=DEFAULT_MEMORY_BUDGET_BYTES / 1024**3
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--start", type=int, default=100)
    parser.add_argument(
        "--maximum",
        type=int,
        default=200_000,
        help="stop doubling here and report a bound rather than inventing a ceiling",
    )
    parser.add_argument(
        "--resolution",
        type=int,
        default=1,
        help="absolute floor on the bisection bracket; at least one, or it cannot terminate",
    )
    parser.add_argument(
        "--resolution-percent",
        type=int,
        default=5,
        help="stop bisecting once the bracket is this fraction of the ceiling",
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument(
        "--confirmation-attempts",
        type=int,
        default=5,
        help="how many times to step the bisected ceiling down before giving up on confirming it",
    )
    parser.add_argument(
        "--reanalyse",
        action="store_true",
        help="re-read results/ceilings.json and rewrite its diagnosis, without measuring anything",
    )
    parser.add_argument("--records-per-vehicle", type=int, default=20)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    add_output_argument(parser)
    arguments = parser.parse_args()

    if arguments.reanalyse:
        reanalyse(arguments)
        return

    print("building the Rust backends...", file=sys.stderr)
    build_rust_backends()

    print(
        f"\nfeasible at n  <=>  peak RSS <= {arguments.memory_budget_gb:.0f} GB "
        f"and wall clock <= {arguments.timeout:.0f}s\n"
        f"records per vehicle {arguments.records_per_vehicle}, "
        f"{arguments.repetitions} repetitions below each ceiling\n"
    )

    findings = {}
    for backend in arguments.backend:
        print(f"  {backend}", flush=True)
        finding = find_ceiling(backend, arguments)
        if finding.get("ceiling"):
            print(
                f"    confirming n={finding['ceiling']} over {arguments.repetitions} runs",
                flush=True,
            )
            confirmation = confirm(backend, finding["ceiling"], arguments)
            finding["bisected_ceiling"] = finding["ceiling"]
            finding["ceiling"] = confirmation["confirmed"]
            finding["confirmation_attempts"] = confirmation["attempts"]
            if confirmation["confirmed"] is not None:
                finding["below_the_ceiling"] = confirmation["measured"]
                stepped = finding["bisected_ceiling"] - confirmation["confirmed"]
                if stepped:
                    print(
                        f"    stepped down {stepped} from the bisected {finding['bisected_ceiling']}"
                        f" — feasibility is not deterministic at the boundary",
                        flush=True,
                    )
            else:
                finding["stopped_because"] = (
                    f"the bisected ceiling {finding['bisected_ceiling']} did not hold across "
                    f"{arguments.repetitions} repetitions, and stepping down did not recover it"
                )
        finding["diagnosis"] = diagnose(finding["probes"])
        if finding["diagnosis"]["peak_rss_saturated"]:
            print(f"    NOTE: {finding['diagnosis']['note']}")
        findings[backend] = finding
        print()

    print(f"{'backend':<10} {'ceiling':>12} {'bisected':>10} {'first infeasible':>18} {'why':<40}")
    print("-" * 94)
    for backend, finding in findings.items():
        ceiling = finding.get("ceiling")
        shown = str(ceiling) if ceiling else f"> {finding['at_least']}" if finding.get("at_least") else "—"
        bisected = finding.get("bisected_ceiling", "—")
        first = finding.get("first_infeasible", "—")
        why = finding.get("stopped_because", "")
        if not why and first != "—":
            why = f"limited by {finding.get('limited_by')} at n={first}"
        print(f"{backend:<10} {shown:>12} {str(bisected):>10} {str(first):>18} {why[:40]:<40}")

    print(f"\n{'backend':<10} {'at n':>10} {'seconds (median, min-max)':>34} {'peak GB (median, min-max)':>34}")
    print("-" * 92)
    for backend, finding in findings.items():
        below = finding.get("below_the_ceiling")
        if not below or "error" in below:
            print(f"{backend:<10} {'—':>10} {(below or {}).get('error', 'no ceiling found'):>34}")
            continue
        seconds = (
            f"{below['seconds_median']:.1f} "
            f"({below['seconds_minimum']:.1f}-{below['seconds_maximum']:.1f})"
        )
        peak = (
            f"{below['peak_rss_gigabytes_median']:.2f} "
            f"({below['peak_rss_gigabytes_minimum']:.2f}-{below['peak_rss_gigabytes_maximum']:.2f})"
        )
        print(f"{backend:<10} {below['record_count']:>10} {seconds:>34} {peak:>34}")

    output = results_directory(arguments) / "ceilings.json"
    document = merge_with_the_previous_run(
        {
            "memory_budget_gigabytes": arguments.memory_budget_gb,
            "timeout_seconds": arguments.timeout,
            "records_per_vehicle": arguments.records_per_vehicle,
            "search_maximum": arguments.maximum,
            "seed": arguments.seed,
            "blinding_seed": arguments.blinding_seed,
            "backends": findings,
        },
        output,
    )
    output.write_text(json.dumps(document, indent=1) + "\n")
    saturated = [
        backend
        for backend, finding in findings.items()
        if finding.get("diagnosis", {}).get("peak_rss_saturated")
    ]
    if saturated:
        print(
            "\nPeak resident set saturated for: "
            + ", ".join(saturated)
            + ".\nAbove the saturation point those readings understate demand — the operating system"
            "\ncompresses the working set faster than the prover grows it — so the memory budget"
            "\nnever binds and the wall clock is what detects infeasibility. A single-metric"
            "\nfeasibility test would have called these runs comfortable while they were thrashing."
        )

    print(f"\nwritten to {shown_path(output)}")


if __name__ == "__main__":
    main()
