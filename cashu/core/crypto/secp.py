from coincurve import PrivateKey, PublicKey


# We extend the public key to define some operations on points
# Picked from https://github.com/WTRMQDev/secp256k1-zkp-py/blob/master/secp256k1_zkp/__init__.py
class PublicKeyExt(PublicKey):
    def __add__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self.combine([pubkey2])    # type: ignore
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
        if hasattr(privkey, "multiply"):
            return self.multiply(bytes.fromhex(privkey.to_hex()))
        elif hasattr(privkey, "scalar"):
            # If it's a BLS PrivateKey or similar scalar, we can multiply
            from cashu.core.crypto.secp import PrivateKey as SecpPrivateKey
            return self.multiply(bytes.fromhex(SecpPrivateKey(bytes.fromhex(privkey.to_hex())).to_hex()))
        else:
            raise TypeError(f"Can't multiply with non privatekey: {type(privkey)}")

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
PublicKey.__eq__ = PublicKeyExt.__eq__  # type: ignore
PublicKey.to_data = PublicKeyExt.to_data  # type: ignore
