import click

try:
    from ..core.crypto.aes import AESCipher
except ImportError:
    from cashu.core.crypto.aes import AESCipher


class LedgerDecrypt:
    def __init__(self, key: str):
        self.key = key
        self.aes = AESCipher(self.key)

    def decrypt(self, encrypted: str) -> str:
        return self.aes.decrypt(encrypted)

    def encrypt(self, message: bytes) -> str:
        return self.aes.encrypt(message)


@click.group()
def cli():
    """Ledger Decrypt CLI"""
    pass


@cli.command()
@click.option("--message", prompt=True, help="The message to encrypt.")
@click.option(
    "--key",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="The encryption key.",
)
def encrypt(message, key):
    """Encrypt a message."""
    ledger = LedgerDecrypt(key)
    encrypted_message = ledger.encrypt(message.encode())
    click.echo(f"Encrypted message: {encrypted_message}")


@cli.command()
@click.option("--encrypted", prompt=True, help="The encrypted message to decrypt.")
@click.option(
    "--key",
    prompt=True,
    hide_input=True,
    help="The decryption key.",
)
def decrypt(encrypted, key):
    """Decrypt a message."""
    ledger = LedgerDecrypt(key)
    decrypted_message = ledger.decrypt(encrypted)
    click.echo(f"Decrypted message: {decrypted_message}")


if __name__ == "__main__":
    cli()
