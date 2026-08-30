import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mpyc.runtime import mpc

from mpc import binding
from mpc.field import MODULUS
from mpc.protocol import (
    COMMUNICATION_ROUNDS,
    ChallengeBarrier,
    exchange_commitments,
    open_fingerprints,
    share_rows,
)
from bench.backends import add_output_argument, results_directory, shown
from shared import reference, generator
from shared.generator import DEFAULT_BLINDING_SEED, DEFAULT_SEED

ROOT = Path(__file__).resolve().parent.parent


def rows_of(dataset) -> list[list[int]]:
    return [list(record.to_field_elements()) for record in dataset.presented_records]


def dataset_for_party(party: int, arguments, blinding_seed: int | None = None):
    return generator.build(
        "honest",
        arguments.record_count,
        arguments.records_per_vehicle,
        arguments.seed + party,
        blinding_seed if blinding_seed is not None else arguments.blinding_seed + party,
    )


def tamper_one_field(dataset):
    records = list(dataset.presented_records)
    position = next(index for index, record in enumerate(records) if record.active)
    original = records[position]
    records[position] = type(original)(
        record_id=original.record_id,
        active=original.active,
        vehicle_id=original.vehicle_id,
        start=original.start,
        end=original.end,
        origin_hub=original.origin_hub,
        destination_hub=original.destination_hub,
        load_kg=original.load_kg + 1,
    )
    return tuple(records)


async def run_case(name: str, shared_records, published_fingerprint: int, challenge: int) -> dict:
    shared = await share_rows(rows_of_records(shared_records))
    opened = await open_fingerprints(shared, challenge)
    mine = opened[mpc.pid]
    return {
        "case": name,
        "published_by_the_proof": hex(published_fingerprint),
        "computed_from_the_shared_rows": hex(mine),
        "binding_holds": mine == published_fingerprint,
    }


def rows_of_records(records) -> list[list[int]]:
    return [list(record.to_field_elements()) for record in records]


async def main() -> None:
    parser = argparse.ArgumentParser(prog="mpc/witness.py")
    parser.add_argument("--record-count", type=int, default=20)
    parser.add_argument("--records-per-vehicle", type=int, default=2)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--blinding-seed", type=int, default=DEFAULT_BLINDING_SEED)
    add_output_argument(parser)
    arguments, _ = parser.parse_known_args()

    await mpc.start()
    party = mpc.pid
    party_count = len(mpc.parties)

    proved = dataset_for_party(party, arguments)

    shared = await share_rows(rows_of(proved))

    barrier = ChallengeBarrier(
        reference.transcript_commitment(reference.traversals_of(proved)), party_count
    )
    barrier.note_shares_received()

    commitments = await exchange_commitments(barrier)
    challenge, _ = barrier.derive(commitments)

    published = reference.fingerprint(proved.presented_records, challenge)

    cases = []

    opened = await open_fingerprints(shared, challenge)
    cases.append({
        "case": "honest",
        "published_by_the_proof": hex(published),
        "computed_from_the_shared_rows": hex(opened[mpc.pid]),
        "binding_holds": opened[mpc.pid] == published,
    })

    substituted = dataset_for_party(party + 100, arguments)
    shared_records = substituted.presented_records if party == 0 else proved.presented_records
    cases.append(await run_case("substitution", shared_records, published, challenge))

    tampered = tamper_one_field(proved) if party == 0 else proved.presented_records
    cases.append(await run_case("single_field_tamper", tampered, published, challenge))

    await mpc.shutdown()

    if party != 0:
        return

    clean = dataset_for_party(0, arguments)
    dirty = generator.build(
        "bad_hub",
        arguments.record_count,
        arguments.records_per_vehicle,
        arguments.seed,
        arguments.blinding_seed,
    )
    ordering = binding.challenge_ordering(clean.presented_records, dirty.presented_records)

    report = {
        "parties": party_count,
        "record_count": arguments.record_count,
        "field_modulus": str(MODULUS),
        "protocol": {
            "communication_rounds": COMMUNICATION_ROUNDS,
            "multiplications_between_shared_values": 0,
            "challenge_derived_from": f"all {party_count} commitments",
            "commitment_covers": "every traversal, index-aligned",
        },
        "cases": cases,
        "challenge_ordering": ordering,
    }

    print(f"\nMPyC over BN254's scalar field, {party_count} parties, "
          f"{arguments.record_count} records each\n")
    print(f"{'case':<22} {'binding holds':<15} {'what it demonstrates'}")
    print("-" * 96)
    meanings = {
        "honest": "the fingerprints agree when nothing is wrong",
        "substitution": "two valid datasets, two valid proofs — only the binding notices",
        "single_field_tamper": "one field changed after proving",
    }
    for case in cases:
        holds = "yes" if case["binding_holds"] else "NO — caught"
        print(f"{case['case']:<22} {holds:<15} {meanings[case['case']]}")
    print(
        f"{'challenge_ordering':<22} "
        f"{'NO — caught' if ordering['forgery_fails_once_the_challenge_is_derived'] else 'yes':<15} "
        f"a chosen challenge lets the blinder be solved for; deriving it closes that"
    )

    print(
        f"\nprotocol: {COMMUNICATION_ROUNDS} communication rounds, "
        f"0 multiplications between shared values (enforced)"
    )
    print("MPyC is a functional witness, not a performance baseline — no timing from it is reported")

    output = results_directory(arguments) / "mpc-binding.json"
    output.write_text(json.dumps(report, indent=1) + "\n")
    print(f"\nwritten to {shown(output)}")

    expected = {
        "honest": True,
        "substitution": False,
        "single_field_tamper": False,
    }
    wrong = [case["case"] for case in cases if case["binding_holds"] != expected[case["case"]]]
    if not ordering["forgery_succeeds_under_a_chosen_challenge"]:
        wrong.append("challenge_ordering: the forgery did not work, so the closure proves nothing")
    if not ordering["forgery_fails_once_the_challenge_is_derived"]:
        wrong.append("challenge_ordering: deriving the challenge did not close the forgery")
    if wrong:
        print(f"\nRESULT: unexpected outcome for {', '.join(wrong)}")
        sys.exit(1)
    print("\nRESULT: the binding holds on honest input and catches every substitution")


if __name__ == "__main__":
    mpc.run(main())
