import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.backends import (
    BackendError,
    add_output_argument,
    build_rust_backends,
    results_directory,
    run_backend,
    shown,
)
from shared import dataset_file, decomposition, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED
from shared.schema import scattered_hub_whitelist

BACKENDS = ("noir", "groth16", "nova")

UNITS = {
    "noir": ("acir_opcodes", "ultrahonk_gates"),
    "groth16": ("constraints",),
    "nova": ("step_constraints",),
}

RECORD_COUNTS = (50, 200, 800)
WHITELIST_SIZE = 8
RECORDS_PER_VEHICLE = 20

STEP_CIRCUIT_RECORD_COUNT = 200
FLAT_IN_RECORD_COUNT = ("nova",)

TIMING_RECORD_COUNT = 200
TIMING_REPETITIONS = 3


def costs_of(report: dict, backend: str) -> dict:
    return {unit: report.get(unit) for unit in UNITS[backend]}


def prove_seconds(report: dict) -> float:
    return sum(
        seconds
        for phase, seconds in report["phases"].items()
        if phase not in ("synthesis", "verify")
    )


def record_counts_for(backend: str) -> tuple[int, ...]:
    return (
        (STEP_CIRCUIT_RECORD_COUNT,) if backend in FLAT_IN_RECORD_COUNT else RECORD_COUNTS
    )


def dataset_for(record_count: int, arguments) -> Path:
    dataset = generator.build(
        "honest",
        record_count,
        arguments.records_per_vehicle,
        arguments.seed,
        arguments.blinding_seed,
        allowed_hubs=scattered_hub_whitelist(arguments.whitelist_size),
    )
    return dataset_file.write(dataset)


def measure(arguments, paths: dict) -> tuple[list[dict], dict, dict]:
    rows: list[dict] = []
    lookup: dict = {}
    published: dict = {}

    total = len(decomposition.CONFIGURATIONS) * len(RECORD_COUNTS)
    done = 0
    for configuration, switches in decomposition.CONFIGURATIONS.items():
        enabled = decomposition.validate(switches)
        for record_count in RECORD_COUNTS:
            done += 1
            entry = {
                "configuration": configuration,
                "record_count": record_count,
                "enabled": list(enabled),
                "backends": {},
            }
            for backend in arguments.backend:
                if record_count not in record_counts_for(backend):
                    continue
                try:
                    report = run_backend(
                        backend, paths[record_count], enable=enabled, timeout=arguments.timeout
                    )
                except BackendError as error:
                    entry["backends"][backend] = {"error": str(error)}
                    print(f"    {backend}: FAILED — {str(error).splitlines()[0]}", flush=True)
                    continue
                if not report["verified"]:
                    entry["backends"][backend] = {
                        **costs_of(report, backend),
                        "error": "the honest dataset did not verify",
                    }
                    print(f"    {backend}: did not verify", flush=True)
                    continue
                measured = costs_of(report, backend)
                entry["backends"][backend] = measured
                for unit, value in measured.items():
                    lookup[(configuration, record_count, backend, unit)] = value
                published.setdefault((backend, record_count), {})[configuration] = {
                    "commitment": report.get("commitment"),
                    "fingerprint": report.get("fingerprint"),
                }
            if entry["backends"]:
                rows.append(entry)
                print(
                    f"  [{done:>3}/{total}] {configuration:<24} n={record_count:<5} "
                    + "  ".join(
                        f"{backend}: {entry['backends'][backend]}"
                        for backend in entry["backends"]
                    ),
                    flush=True,
                )
    return rows, lookup, published


def check_the_absorbed_fields(published: dict) -> dict:

    def partition_of(configuration: str) -> tuple:
        enabled = set(decomposition.CONFIGURATIONS[configuration])
        return (
            "commitment" in enabled,
            "fingerprint" in enabled,
            {"order1", "product1"} & enabled != set(),
            {"order2", "product2"} & enabled != set(),
        )

    groups: dict = {}
    for (backend, record_count), by_configuration in published.items():
        for configuration, values in by_configuration.items():
            key = (backend, record_count, partition_of(configuration))
            groups.setdefault(key, {})[configuration] = values

    agreements = []
    holds = True
    for (backend, record_count, partition), by_configuration in sorted(
        groups.items(), key=lambda item: (item[0][0], item[0][1], str(item[0][2]))
    ):
        commitments = {entry["commitment"] for entry in by_configuration.values()}
        fingerprints = {entry["fingerprint"] for entry in by_configuration.values()}
        agreed = len(commitments) == 1 and len(fingerprints) == 1
        holds = holds and agreed
        carries_commitment, carries_fingerprint, carries_key1, carries_key2 = partition
        agreements.append(
            {
                "backend": backend,
                "record_count": record_count,
                "carries": {
                    "commitment": carries_commitment,
                    "fingerprint": carries_fingerprint,
                    "key1_lane": carries_key1,
                    "key2_lane": carries_key2,
                },
                "configurations_compared": sorted(by_configuration),
                "commitment": sorted(commitments)[0]
                if len(commitments) == 1
                else sorted(commitments),
                "fingerprint": sorted(fingerprints)[0]
                if len(fingerprints) == 1
                else sorted(fingerprints),
                "agreed": agreed,
            }
        )
    return {
        "holds": holds,
        "groups": agreements,
    }


def circuit_neutrality(arguments, paths: dict) -> dict:
    every_switch = decomposition.validate(decomposition.SWITCHES)
    reproduced = {}
    holds = True
    notes = []
    for backend in arguments.backend:
        if STEP_CIRCUIT_RECORD_COUNT not in record_counts_for(backend):
            continue
        path = paths[STEP_CIRCUIT_RECORD_COUNT]
        try:
            undecomposed = run_backend(backend, path, timeout=arguments.timeout)
            decomposed = run_backend(backend, path, enable=every_switch, timeout=arguments.timeout)
        except BackendError as error:
            holds = False
            notes.append(f"{backend}: {error}")
            reproduced[backend] = {"error": str(error)}
            continue
        without_the_flag = costs_of(undecomposed, backend)
        with_every_switch = costs_of(decomposed, backend)
        agreed = without_the_flag == with_every_switch
        holds = holds and agreed
        if not agreed:
            notes.append(
                f"{backend}: without the flag {without_the_flag}, "
                f"with every switch {with_every_switch}"
            )
        reproduced[backend] = {
            "without_the_enable_flag": without_the_flag,
            "with_every_switch_named": with_every_switch,
            "agreed": agreed,
        }
    return {
        "record_count": STEP_CIRCUIT_RECORD_COUNT,
        "holds": holds,
        "discrepancies": notes,
        "by_backend": reproduced,
    }


def collect_timings(arguments, path: Path) -> list[dict]:
    rows = []
    for configuration in decomposition.TIMED:
        switches = decomposition.CONFIGURATIONS[configuration]
        enabled = decomposition.validate(switches)
        entry = {
            "configuration": configuration,
            "record_count": TIMING_RECORD_COUNT,
            "backends": {},
        }
        for backend in arguments.backend:
            samples = []
            failure = None
            for _ in range(TIMING_REPETITIONS):
                try:
                    report = run_backend(backend, path, enable=enabled, timeout=arguments.timeout)
                except BackendError as error:
                    failure = str(error)
                    break
                samples.append(prove_seconds(report))
            if failure is not None or not samples:
                entry["backends"][backend] = {"error": failure or "no sample completed"}
                continue
            entry["backends"][backend] = {
                "repetitions": len(samples),
                "prove_seconds": round(statistics.median(samples), 3),
                "prove_minimum": round(min(samples), 3),
                "prove_maximum": round(max(samples), 3),
            }
        rows.append(entry)
        print(
            f"  {configuration:<24} "
            + "  ".join(
                f"{backend}: {entry['backends'][backend].get('prove_seconds', 'failed')}s"
                for backend in entry["backends"]
            ),
            flush=True,
        )
    return rows


def slope_per_record(by_count: dict) -> float | None:
    counts = sorted(count for count, value in by_count.items() if value is not None)
    if len(counts) < 2:
        return None
    low, high = counts[0], counts[-1]
    return round((by_count[high] - by_count[low]) / (high - low), 3)


def difference(lookup: dict, backend: str, unit: str, minuend: str, subtrahend: str) -> dict:
    by_count = {}
    for record_count in record_counts_for(backend):
        left = lookup.get((minuend, record_count, backend, unit))
        right = lookup.get((subtrahend, record_count, backend, unit))
        by_count[record_count] = None if left is None or right is None else left - right
    entry = {"by_record_count": {str(count): value for count, value in by_count.items()}}
    slope = slope_per_record(by_count)
    if slope is not None:
        entry["per_record"] = slope
    return entry


def per_backend(lookup: dict, backends, compute) -> dict:
    result = {}
    for backend in backends:
        units = {unit: compute(backend, unit) for unit in UNITS[backend]}
        if any(units.values()):
            result[backend] = units
    return result


ISOLATED_AGAINST = {
    "commitment": ("commitment_only", "bare"),
    "fingerprint": ("fingerprint_only", "bare"),
    "p1": ("p1_completeness", "baseline"),
    "p2": ("p2_currentness", "baseline"),
    "p3": ("p3_compliance", "baseline"),
    "p4": ("p4_load_ratio", "baseline"),
    "order1": ("order1_sortedness", "baseline"),
    "product1": ("product1_permutation", "baseline"),
    "p5": ("p5_no_overlap", "order1_sortedness"),
    "order2": ("order2_sortedness", "baseline"),
    "product2": ("product2_permutation", "baseline"),
    "p6": ("p6_uniqueness", "order2_sortedness"),
}


def derive(lookup: dict, backends) -> dict:

    def isolated(switch: str):
        minuend, subtrahend = ISOLATED_AGAINST[switch]
        return lambda backend, unit: difference(lookup, backend, unit, minuend, subtrahend)

    def in_context(switch: str):
        return lambda backend, unit: difference(
            lookup, backend, unit, "full", decomposition.LEAVE_ONE_OUT[switch]
        )

    isolated_cost = {
        switch: per_backend(lookup, backends, isolated(switch)) for switch in decomposition.SWITCHES
    }
    contextual_cost = {
        switch: per_backend(lookup, backends, in_context(switch)) for switch in decomposition.SWITCHES
    }

    def interaction(switch: str):
        def compute(backend: str, unit: str) -> dict:
            by_count = {}
            for record_count in record_counts_for(backend):
                minuend, subtrahend = ISOLATED_AGAINST[switch]
                alone = lookup.get((minuend, record_count, backend, unit))
                alone_base = lookup.get((subtrahend, record_count, backend, unit))
                full = lookup.get(("full", record_count, backend, unit))
                without = lookup.get(
                    (decomposition.LEAVE_ONE_OUT[switch], record_count, backend, unit)
                )
                if None in (alone, alone_base, full, without):
                    by_count[record_count] = None
                    continue
                by_count[record_count] = (full - without) - (alone - alone_base)
            entry = {"by_record_count": {str(k): v for k, v in by_count.items()}}
            slope = slope_per_record(by_count)
            if slope is not None:
                entry["per_record"] = slope
            return entry

        return compute

    interactions = {
        switch: per_backend(lookup, backends, interaction(switch))
        for switch in decomposition.SWITCHES
    }

    def fraction(numerator: str, denominator: str):
        def compute(backend: str, unit: str) -> dict:
            by_count = {}
            for record_count in record_counts_for(backend):
                top = lookup.get((numerator, record_count, backend, unit))
                bottom = lookup.get((denominator, record_count, backend, unit))
                by_count[str(record_count)] = (
                    None if top is None or not bottom else round(top / bottom, 4)
                )
            return {"by_record_count": by_count}

        return compute

    def shared_anchor_product(backend: str, unit: str) -> dict:
        by_count = {}
        for record_count in record_counts_for(backend):
            both = lookup.get(("both_sigma_machinery", record_count, backend, unit))
            first = lookup.get(("sigma1_machinery", record_count, backend, unit))
            second = lookup.get(("sigma2_machinery", record_count, backend, unit))
            base = lookup.get(("baseline", record_count, backend, unit))
            if None in (both, first, second, base):
                by_count[record_count] = None
                continue
            by_count[record_count] = (first - base) + (second - base) - (both - base)
        entry = {"by_record_count": {str(k): v for k, v in by_count.items()}}
        slope = slope_per_record(by_count)
        if slope is not None:
            entry["per_record"] = slope
        return entry

    def residual(backend: str, unit: str) -> dict:
        by_count = {}
        for record_count in record_counts_for(backend):
            full = lookup.get(("full", record_count, backend, unit))
            bare = lookup.get(("bare", record_count, backend, unit))
            if full is None or bare is None:
                by_count[record_count] = None
                continue
            accounted = 0
            complete = True
            for switch in decomposition.SWITCHES:
                minuend, subtrahend = ISOLATED_AGAINST[switch]
                left = lookup.get((minuend, record_count, backend, unit))
                right = lookup.get((subtrahend, record_count, backend, unit))
                if left is None or right is None:
                    complete = False
                    break
                accounted += left - right
            by_count[record_count] = None if not complete else full - bare - accounted
        entry = {"by_record_count": {str(count): value for count, value in by_count.items()}}
        slope = slope_per_record(by_count)
        if slope is not None:
            entry["per_record"] = slope
        fractions = {}
        for record_count in record_counts_for(backend):
            full = lookup.get(("full", record_count, backend, unit))
            bare = lookup.get(("bare", record_count, backend, unit))
            value = by_count.get(record_count)
            if value is None or full is None or bare is None or full == bare:
                fractions[str(record_count)] = None
            else:
                fractions[str(record_count)] = round(value / (full - bare), 4)
        entry["as_a_fraction_of_the_enforced_cost"] = fractions
        return entry

    def total(backend: str, unit: str) -> dict:
        by_configuration = {}
        for configuration in decomposition.CONFIGURATIONS:
            by_count = {
                count: lookup.get((configuration, count, backend, unit))
                for count in record_counts_for(backend)
            }
            entry = {"by_record_count": {str(k): v for k, v in by_count.items()}}
            slope = slope_per_record(by_count)
            if slope is not None:
                entry["per_record"] = slope
            by_configuration[configuration] = entry
        return by_configuration

    return {
        "isolated_cost": {
            "read_against": {
                switch: {"minuend": pair[0], "subtrahend": pair[1]}
                for switch, pair in ISOLATED_AGAINST.items()
            },
            "measurements": isolated_cost,
        },
        "contextual_cost": {
            "measurements": contextual_cost,
        },
        "interaction": {
            "measurements": interactions,
        },
        "shared_anchor_product": {
            "measurements": per_backend(lookup, backends, shared_anchor_product),
        },
        "structure_fraction": {
            "measurements": per_backend(lookup, backends, fraction("bare", "full")),
        },
        "binding_fraction": {
            "measurements": per_backend(lookup, backends, fraction("baseline", "full")),
        },
        "commitment_fraction": {
            "measurements": per_backend(lookup, backends, fraction("commitment_only", "full")),
        },
        "additivity_residual": {
            "measurements": per_backend(lookup, backends, residual),
        },
        "totals": {
            "measurements": per_backend(lookup, backends, total),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="bench/decomposition.py")
    parser.add_argument("--backend", nargs="+", default=list(BACKENDS))
    parser.add_argument("--whitelist-size", type=int, default=WHITELIST_SIZE)
    parser.add_argument("--records-per-vehicle", type=int, default=RECORDS_PER_VEHICLE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    parser.add_argument("--timeout", type=float, default=1800.0)
    parser.add_argument(
        "--skip-timings",
        action="store_true",
        help="constraint counts only; proving time is secondary and costs ninety runs",
    )
    parser.add_argument(
        "--skip-build", action="store_true", help="trust target/release as it stands"
    )
    add_output_argument(parser)
    arguments = parser.parse_args()
    directory = results_directory(arguments)

    if not arguments.skip_build:
        print("building the Rust backends...", file=sys.stderr)
        build_rust_backends()

    paths = {count: dataset_for(count, arguments) for count in RECORD_COUNTS}

    print("\nare the switches circuit-neutral at `full`?")
    neutrality = circuit_neutrality(arguments, paths)
    for backend, finding in neutrality["by_backend"].items():
        state = "agree" if finding.get("agreed") else "DISAGREE"
        print(f"  {backend:<17} {state}  {finding}")
    if not neutrality["holds"]:
        print(
            "\nstopping: naming every switch does not reproduce the circuit reached with no "
            "--enable flag, so the switches are a rewrite of the statement rather than a partition "
            "of it and every delta below would be untrustworthy.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"\nconstraint counts, {len(decomposition.CONFIGURATIONS)} configurations:")
    rows, lookup, published = measure(arguments, paths)

    absorbed = check_the_absorbed_fields(published)
    print("\nthe absorbed field set, within each group that carries the same quantities:")
    for entry in absorbed["groups"]:
        carries = ",".join(name for name, on in entry["carries"].items() if on) or "nothing"
        print(
            f"  {entry['backend']:<17} n={entry['record_count']:<5} "
            f"{len(entry['configurations_compared'])} configurations carrying {carries:<45} "
            f"{'agree' if entry['agreed'] else 'DISAGREE'}"
        )
    if not absorbed["holds"]:
        print(
            "\nstopping: two configurations that carry the same quantities absorbed different "
            "field sets, so their costs are not comparable and every delta is meaningless.",
            file=sys.stderr,
        )
        sys.exit(1)


    timings = []
    if not arguments.skip_timings:
        print(
            f"\nproving time, {TIMING_REPETITIONS} repetitions at n={TIMING_RECORD_COUNT}, "
            f"{len(decomposition.TIMED)} configurations:"
        )
        timings = collect_timings(arguments, paths[TIMING_RECORD_COUNT])

    derived = derive(lookup, arguments.backend)

    print("\nwhat each switch costs per record, alone and in context, in each backend's own unit")
    for switch in decomposition.SWITCHES:
        for backend, units in derived["isolated_cost"]["measurements"][switch].items():
            for unit, entry in units.items():
                alone = entry.get("per_record")
                context = (
                    derived["contextual_cost"]["measurements"][switch]
                    .get(backend, {})
                    .get(unit, {})
                    .get("per_record")
                )
                if alone is None and context is None:
                    continue
                print(
                    f"  {switch:<11} {backend:<17} {unit:<17} "
                    f"alone {str(alone):>12}  in context {str(context):>12}"
                )

    print("\nthe fractions and the residual")
    for name in ("structure_fraction", "binding_fraction", "commitment_fraction"):
        for backend, units in derived[name]["measurements"].items():
            for unit, entry in units.items():
                print(f"  {name:<20} {backend:<17} {unit:<17} {entry['by_record_count']}")
    for backend, units in derived["additivity_residual"]["measurements"].items():
        for unit, entry in units.items():
            print(
                f"  residual             {backend:<17} {unit:<17} {entry['by_record_count']}  "
                f"as a fraction of the enforced cost: "
                f"{entry['as_a_fraction_of_the_enforced_cost']}"
            )

    output = directory / "decomposition.json"
    output.write_text(
        json.dumps(
            {
                "seed": arguments.seed,
                "blinding_seed": arguments.blinding_seed,
                "whitelist_size": arguments.whitelist_size,
                "records_per_vehicle": arguments.records_per_vehicle,
                "record_counts": list(RECORD_COUNTS),
                "step_circuit_record_count": STEP_CIRCUIT_RECORD_COUNT,
                "repetitions_per_constraint_count": 1,
                "timing": {
                    "record_count": TIMING_RECORD_COUNT,
                    "repetitions": TIMING_REPETITIONS,
                    "configurations": list(decomposition.TIMED),
                },
                "switches": list(decomposition.SWITCHES),
                "configurations": [
                    {
                        "id": configuration,
                        "enabled": list(decomposition.validate(switches)),
                    }
                    for configuration, switches in decomposition.CONFIGURATIONS.items()
                ],
                "units": {backend: list(units) for backend, units in UNITS.items()},
                "backends_decomposed": list(arguments.backend),
                "circuit_neutrality": neutrality,
                "absorbed_field_set_check": absorbed,
                "measurements": rows,
                "prove_seconds": timings,
                "derived": derived,
            },
            indent=1,
        )
        + "\n"
    )
    print(f"\nwritten to {shown(output)}")


if __name__ == "__main__":
    main()
