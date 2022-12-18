import secrets
import base64
import secp256k1
from cffi import FFI
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from . import bech32

class PublicKey:
    def __init__(self, raw_bytes: bytes) -> None:
        self.raw_bytes = raw_bytes

    def bech32(self) -> str:
        converted_bits = bech32.convertbits(self.raw_bytes, 8, 5)
        return bech32.bech32_encode("npub", converted_bits, bech32.Encoding.BECH32)

    def hex(self) -> str:
        return self.raw_bytes.hex()

    def verify_signed_message_hash(self, hash: str, sig: str) -> bool:
        pk = secp256k1.PublicKey(b"\x02" + self.raw_bytes, True)
        return pk.schnorr_verify(bytes.fromhex(hash), bytes.fromhex(sig), None, True)

class PrivateKey:
    def __init__(self, raw_secret: bytes=None) -> None:
        if not raw_secret is None:
            self.raw_secret = raw_secret
        else:
            self.raw_secret = secrets.token_bytes(32)

        sk = secp256k1.PrivateKey(self.raw_secret)
        self.public_key = PublicKey(sk.pubkey.serialize()[1:])

    def bech32(self) -> str:
        converted_bits = bech32.convertbits(self.raw_secret, 8, 5)
        return bech32.bech32_encode("nsec", converted_bits, bech32.Encoding.BECH32)

    def hex(self) -> str:
        return self.raw_secret.hex()

    def tweak_add(self, scalar: bytes) -> bytes:
        sk = secp256k1.PrivateKey(self.raw_secret)
        return sk.tweak_add(scalar)

    def compute_shared_secret(self, public_key_hex: str) -> bytes:
        pk = secp256k1.PublicKey(bytes.fromhex("02" + public_key_hex), True)
        return pk.ecdh(self.raw_secret, hashfn=copy_x)

    def encrypt_message(self, message: str, public_key_hex: str) -> str:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.compute_shared_secret(public_key_hex)), modes.CBC(iv))

        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        return f"{base64.b64encode(encrypted_message).decode()}?iv={base64.b64encode(iv).decode()}"

    def decrypt_message(self, encoded_message: str, public_key_hex: str) -> str:
        encoded_data = encoded_message.split('?iv=')
        encoded_content, encoded_iv = encoded_data[0], encoded_data[1]

        iv = base64.b64decode(encoded_iv)
        cipher = Cipher(algorithms.AES(self.compute_shared_secret(public_key_hex)), modes.CBC(iv))
        encrypted_content = base64.b64decode(encoded_content)

        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_content) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_message) + unpadder.finalize()

        return unpadded_data.decode()

    def sign_message_hash(self, hash: bytes) -> str:
        sk = secp256k1.PrivateKey(self.raw_secret)
        sig = sk.schnorr_sign(hash, None, raw=True)
        return sig.hex()

ffi = FFI()
@ffi.callback("int (unsigned char *, const unsigned char *, const unsigned char *, void *)")
def copy_x(output, x32, y32, data):
    ffi.memmove(output, x32, 32)
    return 1