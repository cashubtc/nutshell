from Cryptodome import Random
from Cryptodome.Cipher import AES

plain_text = "This is the text to encrypts"

# encrypted = "7mH9jq3K9xNfWqIyu9gNpUz8qBvGwsrDJ+ACExdV1DvGgY8q39dkxVKeXD7LWCDrPnoD/ZFHJMRMis8v9lwHfNgJut8EVTMuJJi8oTgJevOBXl+E+bJPwej9hY3k20rgCQistNRtGHUzdWyOv7S1tg==".encode()
# iv = "GzDzqOVShWu3Pl2313FBpQ==".encode()

key = bytes.fromhex("3aa925cb69eb613e2928f8a18279c78b1dca04541dfd064df2eda66b59880795")

BLOCK_SIZE = 16


class AESCipher(object):
    """This class is compatible with crypto.createCipheriv('aes-256-cbc')"""

    def __init__(self, key=None):
        self.key = key

    def pad(self, data):
        length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        return data + (chr(length) * length).encode()

    def unpad(self, data):
        return data[: -(data[-1] if type(data[-1]) == int else ord(data[-1]))]

    def encrypt(self, plain_text):
        cipher = AES.new(self.key, AES.MODE_CBC)
        b = plain_text.encode("UTF-8")
        return cipher.iv, cipher.encrypt(self.pad(b))

    def decrypt(self, iv, enc_text):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        return self.unpad(cipher.decrypt(enc_text).decode("UTF-8"))


if __name__ == "__main__":
    aes = AESCipher(key=key)
    iv, enc_text = aes.encrypt(plain_text)
    dec_text = aes.decrypt(iv, enc_text)
    print(dec_text)
