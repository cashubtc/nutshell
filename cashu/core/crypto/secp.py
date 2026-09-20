import os

from coincurve import PrivateKey, PublicKey
from coincurve._libsecp256k1 import ffi, lib


# We extend the public key to define some operations on points
# Picked from https://github.com/WTRMQDev/secp256k1-zkp-py/blob/master/secp256k1_zkp/__init__.py
class PublicKeyExt(PublicKey):
    def __add__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self.combine([pubkey2])  # type: ignore
        else:
            raise TypeError(f"Can't add pubkey and {pubkey2.__class__}")

    def __neg__(self):
        serialized = self.format()
        first_byte, remainder = serialized[:1], serialized[1:]
        # flip odd/even byte
        first_byte = {b"\x03": b"\x02", b"\x02": b"\x03"}[first_byte]
        return PublicKey(first_byte + remainder)

    def __sub__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self + (-pubkey2)  # type: ignore
        else:
            raise TypeError(f"Can't add pubkey and {pubkey2.__class__}")

    def __mul__(self, privkey):
        if isinstance(privkey, PrivateKey):
            return self.multiply(privkey.secret)
        else:
            raise TypeError("Can't multiply with non privatekey")

    def multiply(self, scalar: bytes, update: bool = False) -> PublicKey:
        """Compute s*P as ((s+t) mod n)*P - t*P with a fresh random mask.

        Accept a nonzero scalar of at most 32 bytes, left-padding short inputs.
        Scalar addition stays in libsecp256k1. Retry if t or s+t is invalid,
        since Coincurve cannot represent the point at infinity.

        This is scalar masking, not a constant-time guarantee: both native
        multiplications remain variable-time and their leakage can correlate.
        """
        # Timing rationale: u = (s + t) mod n for group order n, so u*P - t*P
        # equals s*P. A fresh full-width mask randomizes both scalars on every call,
        # making repeated direct observation of the secret's execution harder.
        #
        # For an idealized model, fix P, take t uniform modulo n, and ignore the
        # negligible rejected-mask cases and setup/subtraction costs. Let f(x)
        # be the multiplication time and ε independent, zero-mean noise:
        #
        #   Rₛ = f(t) + f(u) + ε              (observed total duration)
        #   μ = E[f(t)], σ² = Var[f(t)], σₑ² = Var[ε]
        #   E[Rₛ] = 2μ                       (independent of s)
        #   C(s) = E[(f(t) - μ) · (f(u) - μ)]
        #   Var[Rₛ] = 2σ² + 2C(s) + σₑ²
        #
        # Each share is individually uniform in this model, but their timings
        # can correlate because u - t = s mod n. In the remote total-duration
        # model, the observer has no separate timing oracle for a particular t.
        # Estimating their variance v̂ does not directly reveal C(s):
        #
        #   Ĉ(s) = (v̂ - 2σ² - σₑ²) / 2
        #
        # This requires calibrated multiplication/noise variances, or another
        # way to remove those unknown contributions. Even then, an attack needs
        # an efficient relationship between C(s) and secret bits. These equations
        # alone demonstrate neither useful leakage nor practical key recovery.
        # Masking is intended to strengthen resistance to remote timing attacks;
        # the underlying multiplications still have variable-time execution.
        ctx = self.context.ctx
        if len(scalar) > 32:
            raise ValueError("Secret scalar must be at most 32 bytes.")
        scalar = scalar.rjust(32, b"\x00")
        if not lib.secp256k1_ec_seckey_verify(ctx, scalar):
            raise ValueError("Secret scalar must be nonzero and below the group order.")

        while True:
            mask = os.urandom(32)
            if not lib.secp256k1_ec_seckey_verify(ctx, mask):
                continue
            masked_scalar = ffi.new("unsigned char [32]", scalar)
            if lib.secp256k1_ec_seckey_tweak_add(ctx, masked_scalar, mask):
                break

        masked_point = ffi.new("secp256k1_pubkey *", self.public_key[0])
        mask_point = ffi.new("secp256k1_pubkey *", self.public_key[0])
        if not lib.secp256k1_ec_pubkey_tweak_mul(ctx, masked_point, masked_scalar):
            raise ValueError("Masked point multiplication failed.")
        if not lib.secp256k1_ec_pubkey_tweak_mul(ctx, mask_point, mask):
            raise ValueError("Mask point multiplication failed.")
        if not lib.secp256k1_ec_pubkey_negate(ctx, mask_point):
            raise ValueError("Mask point negation failed.")

        result = ffi.new("secp256k1_pubkey *")
        if not lib.secp256k1_ec_pubkey_combine(
            ctx, result, [masked_point, mask_point], 2
        ):
            raise ValueError("Masked point combination failed.")

        if update:
            self.public_key = result
            return self
        return PublicKey(result, self.context)

    def __eq__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            seq1 = self.to_data()
            seq2 = pubkey2.to_data()  # type: ignore
            return seq1 == seq2
        else:
            raise TypeError(f"Can't compare pubkey and {pubkey2.__class__}")

    def to_data(self):
        assert self.public_key
        return [self.public_key.data[i] for i in range(64)]


# Horrible monkeypatching
PublicKey.__add__ = PublicKeyExt.__add__  # type: ignore
PublicKey.__neg__ = PublicKeyExt.__neg__  # type: ignore
PublicKey.__sub__ = PublicKeyExt.__sub__  # type: ignore
PublicKey.__mul__ = PublicKeyExt.__mul__  # type: ignore
PublicKey.multiply = PublicKeyExt.multiply  # type: ignore
PublicKey.__eq__ = PublicKeyExt.__eq__  # type: ignore
PublicKey.to_data = PublicKeyExt.to_data  # type: ignore
