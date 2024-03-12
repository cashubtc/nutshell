import click

try:
    from ..core.crypto.aes import AESCipher
except ImportError:
    # for the CLI to work
    from cashu.core.crypto.aes import AESCipher
import asyncio
from functools import wraps

from cashu.core.db import Database, table_with_schema
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.mint import migrations
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.ledger import Ledger


# https://github.com/pallets/click/issues/85#issuecomment-503464628
def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


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
    aes = AESCipher(key)
    encrypted_message = aes.encrypt(message.encode())
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
    aes = AESCipher(key)
    decrypted_message = aes.decrypt(encrypted)
    click.echo(f"Decrypted message: {decrypted_message}")


# command to migrate the database to encrypted seeds
@cli.command()
@coro
@click.option("--no-dry-run", is_flag=True, help="Dry run.", default=False)
async def migrate(no_dry_run):
    """Migrate the database to encrypted seeds."""
    ledger = Ledger(
        db=Database("mint", settings.mint_database),
        seed=settings.mint_private_key,
        seed_decryption_key=settings.mint_seed_decryption_key,
        derivation_path=settings.mint_derivation_path,
        backends={},
        crud=LedgerCrudSqlite(),
    )
    assert settings.mint_seed_decryption_key, "MINT_SEED_DECRYPTION_KEY not set."
    assert (
        len(settings.mint_seed_decryption_key) > 12
    ), "MINT_SEED_DECRYPTION_KEY is too short, must be at least 12 characters."
    click.echo(
        "Decryption key:"
        f" {settings.mint_seed_decryption_key[0]}{'*'*10}{settings.mint_seed_decryption_key[-1]}"
    )

    aes = AESCipher(settings.mint_seed_decryption_key)

    click.echo("Making sure that db is migrated to latest version first.")
    await migrate_databases(ledger.db, migrations)

    # get all keysets
    async with ledger.db.connect() as conn:
        rows = await conn.fetchall(
            f"SELECT * FROM {table_with_schema(ledger.db, 'keysets')} WHERE seed IS NOT"
            " NULL"
        )
    click.echo(f"Found {len(rows)} keysets in database.")
    keysets_all = [dict(**row) for row in rows]
    keysets_migrate = []
    # encrypt the seeds
    for keyset_dict in keysets_all:
        if keyset_dict["seed"] and not keyset_dict["encrypted_seed"]:
            keyset_dict["encrypted_seed"] = aes.encrypt(keyset_dict["seed"].encode())
            keyset_dict["seed_encryption_method"] = "aes"
            keysets_migrate.append(keyset_dict)
        else:
            click.echo(f"Skipping keyset {keyset_dict['id']}: already migrated.")

    click.echo(f"There are {len(keysets_migrate)} keysets to migrate.")

    for keyset_dict in keysets_migrate:
        click.echo(f"Keyset {keyset_dict['id']}")
        click.echo(f"  Encrypted seed: {keyset_dict['encrypted_seed']}")
        click.echo(f"  Encryption method: {keyset_dict['seed_encryption_method']}")
        decryption_success_str = (
            "✅"
            if aes.decrypt(keyset_dict["encrypted_seed"]) == keyset_dict["seed"]
            else "❌"
        )
        click.echo(f"  Seed decryption test: {decryption_success_str}")

    if not no_dry_run:
        click.echo(
            "This was a dry run. Use --no-dry-run to apply the changes to the database."
        )
    if no_dry_run and keysets_migrate:
        click.confirm(
            "Are you sure you want to continue? Before you continue, make sure to have"
            " a backup of your keysets database table.",
            abort=True,
        )
        click.echo("Updating keysets in the database.")
        async with ledger.db.connect() as conn:
            for keyset_dict in keysets_migrate:
                click.echo(f"Updating keyset {keyset_dict['id']}")
                await conn.execute(
                    f"UPDATE {table_with_schema(ledger.db, 'keysets')} SET seed='',"
                    " encrypted_seed = ?, seed_encryption_method = ? WHERE id = ?",
                    (
                        keyset_dict["encrypted_seed"],
                        keyset_dict["seed_encryption_method"],
                        keyset_dict["id"],
                    ),
                )
        click.echo("✅ Migration complete.")


if __name__ == "__main__":
    cli()
