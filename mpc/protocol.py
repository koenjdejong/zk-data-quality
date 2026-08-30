from mpyc.runtime import mpc

from mpc.field import MODULUS, forbid_multiplication_between_shares, secure_type
from shared.reference import derive_challenges

COMMUNICATION_ROUNDS = 2


def coefficients(fingerprint_challenge: int, field_element_count: int) -> list[int]:
    powers = []
    power = 1
    for _ in range(field_element_count):
        powers.append(power)
        power = power * fingerprint_challenge % MODULUS
    return powers


def flatten(rows) -> list[int]:
    return [value for row in rows for value in row]


async def share_rows(own_rows) -> list:
    secure = secure_type()
    own_stream = [secure(value % MODULUS) for value in flatten(own_rows)]
    return mpc.input(own_stream)


async def open_fingerprints(shared_streams, fingerprint_challenge: int) -> list[int]:
    secure = secure_type()
    with forbid_multiplication_between_shares(secure):
        fingerprints = []
        for stream in shared_streams:
            powers = coefficients(fingerprint_challenge, len(stream))
            fingerprints.append(sum(share * power for share, power in zip(stream, powers)))

    opened = await mpc.output(fingerprints)
    return [int(value) % MODULUS for value in opened]


class ChallengeBarrier:

    def __init__(self, commitment: int, party_count: int):
        self.commitment = commitment % MODULUS
        self.party_count = party_count
        self._shares_received = False

    def note_shares_received(self) -> None:
        self._shares_received = True

    def release(self) -> int:
        if not self._shares_received:
            raise RuntimeError(
                "the commitment may not be published before this party holds shares from every "
                "other party: releasing it early lets the others derive a challenge while this "
                "party's own input is still free to change"
            )
        return self.commitment

    def derive(self, commitments) -> tuple[int, int]:
        commitments = list(commitments)
        if len(commitments) != self.party_count:
            raise RuntimeError(
                f"a challenge needs all {self.party_count} commitments, got {len(commitments)}"
            )
        return derive_challenges(commitments)


async def exchange_commitments(barrier: ChallengeBarrier) -> list[int]:
    secure = mpc.SecFld(modulus=MODULUS)
    released = barrier.release()
    shared = mpc.input(secure(released))
    opened = await mpc.output(shared)
    return [int(value) % MODULUS for value in opened]


