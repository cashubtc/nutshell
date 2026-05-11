from coincurve import PrivateKey as CoincurvePrivateKey
from coincurve import PublicKey as CoincurvePublicKey

from .interfaces import ICashuPrivateKey, ICashuPublicKey


class SecpPublicKey(CoincurvePublicKey, ICashuPublicKey):
    def __add__(self, pubkey2):
        if isinstance(pubkey2, CoincurvePublicKey):
            return self.combine([pubkey2])    # type: ignore
        else:
            raise TypeError(f"Can't add pubkey and {pubkey2.__class__}")

    def __neg__(self):
        serialized = self.format()
        first_byte, remainder = serialized[:1], serialized[1:]
        # flip odd/even byte
        first_byte = {b"\x03": b"\x02", b"\x02": b"\x03"}[first_byte]
        return SecpPublicKey(first_byte + remainder)

    def __sub__(self, pubkey2):
        if isinstance(pubkey2, CoincurvePublicKey):
            # Convert to SecpPublicKey if it's just a CoincurvePublicKey
            if not isinstance(pubkey2, SecpPublicKey):
                pubkey2 = SecpPublicKey(pubkey2.format())
            return self + (-pubkey2)  # type: ignore
        else:
            raise TypeError(f"Can't add pubkey and {pubkey2.__class__}")

    def __mul__(self, privkey):
        if isinstance(privkey, SecpPrivateKey):
            return SecpPublicKey(self.multiply(bytes.fromhex(privkey.to_hex())).format())
        else:
            raise TypeError("Can't multiply with non privatekey")

    def __eq__(self, pubkey2):
        if isinstance(pubkey2, CoincurvePublicKey):
            seq1 = self.to_data()
            seq2 = pubkey2.to_data()  # type: ignore
            return seq1 == seq2
        else:
            raise TypeError(f"Can't compare pubkey and {pubkey2.__class__}")

    def to_data(self):
        assert self.public_key
        return [self.public_key.data[i] for i in range(64)]

    def serialize(self) -> bytes:
        return self.format()

class SecpPrivateKey(CoincurvePrivateKey, ICashuPrivateKey):
    def to_hex(self) -> str:
        return super().to_hex()


