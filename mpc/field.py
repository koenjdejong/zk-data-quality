from mpyc.runtime import mpc

from shared.schema import BN254_SCALAR_FIELD_MODULUS

MODULUS = BN254_SCALAR_FIELD_MODULUS


def secure_type():
    secure = mpc.SecFld(modulus=MODULUS)
    assert secure.field.modulus == MODULUS, "the MPC field is not the ZKP field"
    return secure


class MultiplicationBetweenSharesForbidden(RuntimeError):
    pass


class forbid_multiplication_between_shares:

    def __init__(self, secure):
        self.secure = secure
        self.original = None

    def __enter__(self):
        secure = self.secure
        self.original = secure.__mul__

        def guarded(left, right):
            if isinstance(right, secure):
                raise MultiplicationBetweenSharesForbidden(
                    "the binding protocol multiplied two shared values; the fingerprint is a linear "
                    "form and must need only public coefficients"
                )
            return self.original(left, right)

        secure.__mul__ = guarded
        return self

    def __exit__(self, *_):
        self.secure.__mul__ = self.original
        return False
