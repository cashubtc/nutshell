import hashlib

from cashu.core.crypto.secp import PrivateKey, PublicKey


def sign_p2pk_pubkey(private_key: PrivateKey):
    assert private_key.pubkey
    message = private_key.pubkey.serialize()
    signature = private_key.ecdsa_serialize(private_key.ecdsa_sign(message))
    return signature.hex()


def verify_p2pk_signature(message: bytes, pubkey: PublicKey, signature: bytes):
    return pubkey.ecdsa_verify(message, pubkey_verify.ecdsa_deserialize(signature))


if __name__ == "__main__":
    # generate keys
    private_key_bytes = b"12300000000000000000000000000123"
    private_key = PrivateKey(private_key_bytes, raw=True)
    print(private_key.serialize())
    public_key = private_key.pubkey
    assert public_key
    print(public_key.serialize().hex())

    # sign message (=pubkey)
    message = public_key.serialize()
    signature = private_key.ecdsa_serialize(private_key.ecdsa_sign(message))
    print(signature.hex())

    # verify
    pubkey_verify = PublicKey(message, raw=True)
    print(public_key.ecdsa_verify(message, pubkey_verify.ecdsa_deserialize(signature)))
