import copy
from typing import Dict, List

from ..core.base import MeltQuoteState, MintKeyset, MintQuoteState, Proof
from ..core.crypto.keys import derive_keyset_id, derive_keyset_id_deprecated
from ..core.db import Connection, Database
from ..core.settings import settings


async def m000_create_migrations_table(conn: Connection):
    await conn.execute(
        f"""
    CREATE TABLE IF NOT EXISTS {conn.table_with_schema('dbversions')} (
        db TEXT PRIMARY KEY,
        version INT NOT NULL
    )
    """
    )


async def m001_initial(db: Database):
    async with db.connect() as conn:
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('promises')} (
                    amount {db.big_int} NOT NULL,
                    b_b TEXT NOT NULL,
                    c_b TEXT NOT NULL,

                    UNIQUE (b_b)

                );
            """
        )

        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('proofs_used')} (
                    amount {db.big_int} NOT NULL,
                    c TEXT NOT NULL,
                    secret TEXT NOT NULL,

                    UNIQUE (secret)

                );
            """
        )

        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('invoices')} (
                    amount {db.big_int} NOT NULL,
                    pr TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    issued BOOL NOT NULL,

                    UNIQUE (hash)

                );
            """
        )


async def drop_balance_views(db: Database, conn: Connection):
    await conn.execute(f"DROP VIEW IF EXISTS {db.table_with_schema('balance')}")
    await conn.execute(f"DROP VIEW IF EXISTS {db.table_with_schema('balance_issued')}")
    await conn.execute(
        f"DROP VIEW IF EXISTS {db.table_with_schema('balance_redeemed')}"
    )


async def create_balance_views(db: Database, conn: Connection):
    await conn.execute(
        f"""
        CREATE VIEW {db.table_with_schema('balance_issued')} AS
        SELECT COALESCE(SUM(s), 0) AS balance FROM (
            SELECT SUM(amount) AS s
            FROM {db.table_with_schema('promises')}
            WHERE amount > 0
        ) AS balance_issued;
    """
    )

    await conn.execute(
        f"""
        CREATE VIEW {db.table_with_schema('balance_redeemed')} AS
        SELECT COALESCE(SUM(s), 0) AS balance FROM (
            SELECT SUM(amount) AS s
            FROM {db.table_with_schema('proofs_used')}
            WHERE amount > 0
        ) AS balance_redeemed;
    """
    )

    await conn.execute(
        f"""
        CREATE VIEW {db.table_with_schema('balance')} AS
        SELECT s_issued - s_used FROM (
            SELECT bi.balance AS s_issued, bu.balance AS s_used
            FROM {db.table_with_schema('balance_issued')} bi
            CROSS JOIN {db.table_with_schema('balance_redeemed')} bu
        ) AS balance;
    """
    )


async def m002_add_balance_views(db: Database):
    async with db.connect() as conn:
        await create_balance_views(db, conn)


async def m003_mint_keysets(db: Database):
    """
    Stores mint keysets from different mints and epochs.
    """
    async with db.connect() as conn:
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('keysets')} (
                    id TEXT NOT NULL,
                    derivation_path TEXT,
                    valid_from TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                    valid_to TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                    first_seen TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
                    active BOOL DEFAULT TRUE,

                    UNIQUE (derivation_path)

                );
            """
        )
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('mint_pubkeys')} (
                    id TEXT NOT NULL,
                    amount {db.big_int} NOT NULL,
                    pubkey TEXT NOT NULL,

                    UNIQUE (id, pubkey)

                );
            """
        )


async def m004_keysets_add_version(db: Database):
    """
    Column that remembers with which version
    """
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('keysets')} ADD COLUMN version TEXT"
        )


async def m005_pending_proofs_table(db: Database) -> None:
    """
    Store pending proofs.
    """
    async with db.connect() as conn:
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('proofs_pending')} (
                    amount {db.big_int} NOT NULL,
                    c TEXT NOT NULL,
                    secret TEXT NOT NULL,

                    UNIQUE (secret)

                );
            """
        )


async def m006_invoices_add_payment_hash(db: Database):
    """
    Column that remembers the payment_hash as we're using
    the column hash as a random identifier now
    (see https://github.com/cashubtc/nuts/pull/14).
    """
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('invoices')} ADD COLUMN payment_hash"
            " TEXT"
        )
        await conn.execute(
            f"UPDATE {db.table_with_schema('invoices')} SET payment_hash = hash"
        )


async def m007_proofs_and_promises_store_id(db: Database):
    """
    Column that stores the id of the proof or promise.
    """
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('proofs_used')} ADD COLUMN id TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('proofs_pending')} ADD COLUMN id TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('promises')} ADD COLUMN id TEXT"
        )


async def m008_promises_dleq(db: Database):
    """
    Add columns for DLEQ proof to promises table.
    """
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('promises')} ADD COLUMN e TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('promises')} ADD COLUMN s TEXT"
        )


async def m009_add_out_to_invoices(db: Database):
    # column in invoices for marking whether the invoice is incoming (out=False) or outgoing (out=True)
    async with db.connect() as conn:
        # rename column pr to bolt11
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('invoices')} RENAME COLUMN pr TO"
            " bolt11"
        )
        # rename column hash to payment_hash
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('invoices')} RENAME COLUMN hash TO id"
        )

        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('invoices')} ADD COLUMN out BOOL"
        )


async def m010_add_index_to_proofs_used(db: Database):
    # create index on proofs_used table for secret
    async with db.connect() as conn:
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " proofs_used_secret_idx ON"
            f" {db.table_with_schema('proofs_used')} (secret)"
        )


async def m011_add_quote_tables(db: Database):
    async with db.connect() as conn:
        # add column "created" to tables invoices, promises, proofs_used, proofs_pending
        tables = ["invoices", "promises", "proofs_used", "proofs_pending"]
        for table in tables:
            await conn.execute(
                f"ALTER TABLE {db.table_with_schema(table)} ADD COLUMN created"
                " TIMESTAMP"
            )
            await conn.execute(
                f"UPDATE {db.table_with_schema(table)} SET created ="
                f" '{db.timestamp_now_str()}'"
            )

        # add column "witness" to table proofs_used
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('proofs_used')} ADD COLUMN witness"
            " TEXT"
        )

        # add columns "seed" and "unit" to table keysets
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('keysets')} ADD COLUMN seed TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('keysets')} ADD COLUMN unit TEXT"
        )

        # fill columns "seed" and "unit" in table keysets
        await conn.execute(
            f"UPDATE {db.table_with_schema('keysets')} SET seed ="
            f" '{settings.mint_private_key}', unit = 'sat'"
        )

        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('mint_quotes')} (
                    quote TEXT NOT NULL,
                    method TEXT NOT NULL,
                    request TEXT NOT NULL,
                    checking_id TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    amount {db.big_int} NOT NULL,
                    paid BOOL NOT NULL,
                    issued BOOL NOT NULL,
                    created_time TIMESTAMP,
                    paid_time TIMESTAMP,

                    UNIQUE (quote)

                );
            """
        )

        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('melt_quotes')} (
                    quote TEXT NOT NULL,
                    method TEXT NOT NULL,
                    request TEXT NOT NULL,
                    checking_id TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    amount {db.big_int} NOT NULL,
                    fee_reserve {db.big_int},
                    paid BOOL NOT NULL,
                    created_time TIMESTAMP,
                    paid_time TIMESTAMP,
                    fee_paid {db.big_int},
                    proof TEXT,

                    UNIQUE (quote)

                );
            """
        )

        await conn.execute(
            f"INSERT INTO {db.table_with_schema('mint_quotes')} (quote, method,"
            " request, checking_id, unit, amount, paid, issued, created_time,"
            " paid_time) SELECT id, 'bolt11', bolt11, COALESCE(payment_hash, 'None'),"
            f" 'sat', amount, False, issued, COALESCE(created, '{db.timestamp_now_str()}'),"
            f" NULL FROM {db.table_with_schema('invoices')} "
        )

        # drop table invoices
        await conn.execute(f"DROP TABLE {db.table_with_schema('invoices')}")


async def m012_keysets_uniqueness_with_seed(db: Database):
    # copy table keysets to keysets_old, create a new table keysets
    # with the same columns but with a unique constraint on (seed, derivation_path)
    # and copy the data from keysets_old to keysets, then drop keysets_old
    async with db.connect() as conn:
        await conn.execute(
            f"DROP TABLE IF EXISTS {db.table_with_schema('keysets_old')}"
        )
        await conn.execute(
            f"CREATE TABLE {db.table_with_schema('keysets_old')} AS"
            f" SELECT * FROM {db.table_with_schema('keysets')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('keysets')}")
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('keysets')} (
                    id TEXT NOT NULL,
                    derivation_path TEXT,
                    seed TEXT,
                    valid_from TIMESTAMP,
                    valid_to TIMESTAMP,
                    first_seen TIMESTAMP,
                    active BOOL DEFAULT TRUE,
                    version TEXT,
                    unit TEXT,

                    UNIQUE (seed, derivation_path)

                );
            """
        )
        await conn.execute(
            f"INSERT INTO {db.table_with_schema('keysets')} (id,"
            " derivation_path, valid_from, valid_to, first_seen,"
            " active, version, seed, unit) SELECT id, derivation_path,"
            " valid_from, valid_to, first_seen, active, version, seed,"
            f" unit FROM {db.table_with_schema('keysets_old')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('keysets_old')}")


async def m013_keysets_add_encrypted_seed(db: Database):
    async with db.connect() as conn:
        # set keysets table unique constraint to id
        # copy table keysets to keysets_old, create a new table keysets
        # with the same columns but with a unique constraint on id
        # and copy the data from keysets_old to keysets, then drop keysets_old
        await conn.execute(
            f"DROP TABLE IF EXISTS {db.table_with_schema('keysets_old')}"
        )
        await conn.execute(
            f"CREATE TABLE {db.table_with_schema('keysets_old')} AS"
            f" SELECT * FROM {db.table_with_schema('keysets')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('keysets')}")
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('keysets')} (
                    id TEXT NOT NULL,
                    derivation_path TEXT,
                    seed TEXT,
                    valid_from TIMESTAMP,
                    valid_to TIMESTAMP,
                    first_seen TIMESTAMP,
                    active BOOL DEFAULT TRUE,
                    version TEXT,
                    unit TEXT,

                    UNIQUE (id)

                );
            """
        )
        await conn.execute(
            f"INSERT INTO {db.table_with_schema('keysets')} (id,"
            " derivation_path, valid_from, valid_to, first_seen,"
            " active, version, seed, unit) SELECT id, derivation_path,"
            " valid_from, valid_to, first_seen, active, version, seed,"
            f" unit FROM {db.table_with_schema('keysets_old')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('keysets_old')}")

        # add columns encrypted_seed and seed_encryption_method to keysets
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('keysets')} ADD COLUMN encrypted_seed"
            " TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('keysets')} ADD COLUMN"
            " seed_encryption_method TEXT"
        )


async def m014_proofs_add_Y_column(db: Database):
    # get all proofs_used and proofs_pending from the database and compute Y for each of them
    async with db.connect() as conn:
        rows = await conn.fetchall(
            f"SELECT * FROM {db.table_with_schema('proofs_used')}"
        )
        # Proof() will compute Y from secret upon initialization
        proofs_used = [Proof(**r) for r in rows]

        rows = await conn.fetchall(
            f"SELECT * FROM {db.table_with_schema('proofs_pending')}"
        )
        proofs_pending = [Proof(**r) for r in rows]
    async with db.connect() as conn:
        # we have to drop the balance views first and recreate them later
        await drop_balance_views(db, conn)

        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('proofs_used')} ADD COLUMN y TEXT"
        )
        for proof in proofs_used:
            await conn.execute(
                f"UPDATE {db.table_with_schema('proofs_used')} SET y = '{proof.Y}'"
                f" WHERE secret = '{proof.secret}'"
            )
        # Copy proofs_used to proofs_used_old and create a new table proofs_used
        # with the same columns but with a unique constraint on (Y)
        # and copy the data from proofs_used_old to proofs_used, then drop proofs_used_old
        await conn.execute(
            f"DROP TABLE IF EXISTS {db.table_with_schema('proofs_used_old')}"
        )
        await conn.execute(
            f"CREATE TABLE {db.table_with_schema('proofs_used_old')} AS"
            f" SELECT * FROM {db.table_with_schema('proofs_used')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('proofs_used')}")
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('proofs_used')} (
                    amount {db.big_int} NOT NULL,
                    c TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    id TEXT,
                    y TEXT,
                    created TIMESTAMP,
                    witness TEXT,

                    UNIQUE (Y)

                );
            """
        )
        await conn.execute(
            f"INSERT INTO {db.table_with_schema('proofs_used')} (amount, c, "
            "secret, id, y, created, witness) SELECT amount, c, secret, id, y,"
            f" created, witness FROM {db.table_with_schema('proofs_used_old')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('proofs_used_old')}")

        # add column y to proofs_pending
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('proofs_pending')} ADD COLUMN y TEXT"
        )
        for proof in proofs_pending:
            await conn.execute(
                f"UPDATE {db.table_with_schema('proofs_pending')} SET y = '{proof.Y}'"
                f" WHERE secret = '{proof.secret}'"
            )

        # Copy proofs_pending to proofs_pending_old and create a new table proofs_pending
        # with the same columns but with a unique constraint on (Y)
        # and copy the data from proofs_pending_old to proofs_pending, then drop proofs_pending_old
        await conn.execute(
            f"DROP TABLE IF EXISTS {db.table_with_schema('proofs_pending_old')}"
        )

        await conn.execute(
            f"CREATE TABLE {db.table_with_schema('proofs_pending_old')} AS"
            f" SELECT * FROM {db.table_with_schema('proofs_pending')}"
        )

        await conn.execute(f"DROP TABLE {db.table_with_schema('proofs_pending')}")
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('proofs_pending')} (
                    amount {db.big_int} NOT NULL,
                    c TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    y TEXT,
                    id TEXT,
                    created TIMESTAMP DEFAULT {db.timestamp_now},

                    UNIQUE (Y)

                );
            """
        )
        await conn.execute(
            f"INSERT INTO {db.table_with_schema('proofs_pending')} (amount, c, "
            "secret, y, id, created) SELECT amount, c, secret, y, id, created"
            f" FROM {db.table_with_schema('proofs_pending_old')}"
        )

        await conn.execute(f"DROP TABLE {db.table_with_schema('proofs_pending_old')}")

        # recreate the balance views
        await create_balance_views(db, conn)


async def m015_add_index_Y_to_proofs_used_and_pending(db: Database):
    # create index on proofs_used table for Y
    async with db.connect() as conn:
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " proofs_used_Y_idx ON"
            f" {db.table_with_schema('proofs_used')} (Y)"
        )

        await conn.execute(
            "CREATE INDEX IF NOT EXISTS"
            " proofs_pending_Y_idx ON"
            f" {db.table_with_schema('proofs_pending')} (Y)"
        )


async def m016_recompute_Y_with_new_h2c(db: Database):
    # get all proofs_used and proofs_pending from the database and compute Y for each of them
    async with db.connect() as conn:
        rows = await conn.fetchall(
            f"SELECT * FROM {db.table_with_schema('proofs_used')}"
        )
        # Proof() will compute Y from secret upon initialization
        proofs_used = [Proof(**r) for r in rows]
    async with db.connect() as conn:
        rows = await conn.fetchall(
            f"SELECT * FROM {db.table_with_schema('proofs_pending')}"
        )
        proofs_pending = [Proof(**r) for r in rows]

    # Prepare data for batch update
    proofs_used_data = [(proof.Y, proof.secret) for proof in proofs_used]
    proofs_pending_data = [(proof.Y, proof.secret) for proof in proofs_pending]

    # Perform batch update in a single transaction
    async with db.connect() as conn:
        if len(proofs_used_data):
            # For proofs_used
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS tmp_proofs_used (Y TEXT, secret TEXT)"
            )
            values_placeholder = ", ".join(
                f"('{y}', '{secret}')" for y, secret in proofs_used_data
            )
            await conn.execute(
                f"INSERT INTO tmp_proofs_used (y, secret) VALUES {values_placeholder}",
            )
            await conn.execute(
                f"""
                UPDATE {db.table_with_schema('proofs_used')}
                SET y = tmp_proofs_used.y
                FROM tmp_proofs_used
                WHERE {db.table_with_schema('proofs_used')}.secret = tmp_proofs_used.secret
                """
            )

        if len(proofs_pending_data):
            # For proofs_pending
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS tmp_proofs_pending (Y TEXT, secret TEXT)"
            )
            values_placeholder = ", ".join(
                f"('{y}', '{secret}')" for y, secret in proofs_pending_data
            )
            await conn.execute(
                f"INSERT INTO tmp_proofs_used (y, secret) VALUES {values_placeholder}",
            )
            await conn.execute(
                f"""
                UPDATE {db.table_with_schema('proofs_pending')}
                SET y = tmp_proofs_pending.y
                FROM tmp_proofs_pending
                WHERE {db.table_with_schema('proofs_pending')}.secret = tmp_proofs_pending.secret
                """
            )

    async with db.connect() as conn:
        if len(proofs_used_data):
            await conn.execute("DROP TABLE tmp_proofs_used")
        if len(proofs_pending_data):
            await conn.execute("DROP TABLE tmp_proofs_pending")


async def m017_foreign_keys_proof_tables(db: Database):
    """
    Create a foreign key relationship between the keyset id in the proof tables and the keyset table.

    Create a foreign key relationship between the keyset id in the promises table and the keyset table.

    Create a foreign key relationship between the quote id in the melt_quotes
    and the proofs_used and proofs_pending tables.

    NOTE: We do not use ALTER TABLE directly to add the new column with a foreign key relation because SQLIte does not support it.
    """

    async with db.connect() as conn:
        # drop the balance views first
        await drop_balance_views(db, conn)

        # add foreign key constraints to proofs_used table
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('proofs_used_new')} (
                    amount {db.big_int} NOT NULL,
                    id TEXT,
                    c TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    y TEXT,
                    witness TEXT,
                    created TIMESTAMP,
                    melt_quote TEXT,

                    FOREIGN KEY (melt_quote) REFERENCES {db.table_with_schema('melt_quotes')}(quote),

                    UNIQUE (y)
                );
            """
        )
        await conn.execute(
            f"INSERT INTO {db.table_with_schema('proofs_used_new')} (amount, id, c, secret, y, witness, created) SELECT amount, id, c, secret, y, witness, created FROM {db.table_with_schema('proofs_used')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('proofs_used')}")
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('proofs_used_new')} RENAME TO {db.table_with_schema('proofs_used')}"
        )

        # add foreign key constraints to proofs_pending table
        await conn.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {db.table_with_schema('proofs_pending_new')} (
                    amount {db.big_int} NOT NULL,
                    id TEXT,
                    c TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    y TEXT,
                    witness TEXT,
                    created TIMESTAMP,
                    melt_quote TEXT,

                    FOREIGN KEY (melt_quote) REFERENCES {db.table_with_schema('melt_quotes')}(quote),

                    UNIQUE (y)
                );
            """
        )
        await conn.execute(
            f"INSERT INTO {db.table_with_schema('proofs_pending_new')} (amount, id, c, secret, y, created) SELECT amount, id, c, secret, y, created FROM {db.table_with_schema('proofs_pending')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('proofs_pending')}")
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('proofs_pending_new')} RENAME TO {db.table_with_schema('proofs_pending')}"
        )

        # add foreign key constraints to promises table
        await conn.execute(
            f"""
                    CREATE TABLE IF NOT EXISTS {db.table_with_schema('promises_new')} (
                        amount {db.big_int} NOT NULL,
                        id TEXT,
                        b_ TEXT NOT NULL,
                        c_ TEXT NOT NULL,
                        dleq_e TEXT,
                        dleq_s TEXT,
                        created TIMESTAMP,
                        mint_quote TEXT,
                        swap_id TEXT,

                        FOREIGN KEY (mint_quote) REFERENCES {db.table_with_schema('mint_quotes')}(quote),

                        UNIQUE (b_)
                    );
                """
        )

        await conn.execute(
            f"INSERT INTO {db.table_with_schema('promises_new')} (amount, id, b_, c_, dleq_e, dleq_s, created) SELECT amount, id, b_b, c_b, e, s, created FROM {db.table_with_schema('promises')}"
        )
        await conn.execute(f"DROP TABLE {db.table_with_schema('promises')}")
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('promises_new')} RENAME TO {db.table_with_schema('promises')}"
        )

        # recreate the balance views
        await create_balance_views(db, conn)

    # recreate indices
    await m015_add_index_Y_to_proofs_used_and_pending(db)


async def m018_duplicate_deprecated_keyset_ids(db: Database):
    async with db.connect() as conn:
        rows = await conn.fetchall(  # type: ignore
            f"""
                SELECT * from {db.table_with_schema('keysets')}
                """,
        )
        keysets = [MintKeyset(**row) for row in rows]
        duplicated_keysets: list[MintKeyset] = []
        for keyset in keysets:
            keyset_copy = copy.copy(keyset)
            if not keyset_copy.public_keys:
                raise Exception(f"keyset {keyset_copy.id} has no public keys")
            if keyset.version_tuple < (0, 15):
                keyset_copy.id = derive_keyset_id(keyset_copy.public_keys)
            else:
                keyset_copy.id = derive_keyset_id_deprecated(keyset_copy.public_keys)
            duplicated_keysets.append(keyset_copy)

        for keyset in duplicated_keysets:
            await conn.execute(
                f"""
                INSERT INTO {db.table_with_schema('keysets')}
                (id, derivation_path, valid_from, valid_to, first_seen, active, version, seed, unit, encrypted_seed, seed_encryption_method)
                VALUES (:id, :derivation_path, :valid_from, :valid_to, :first_seen, :active, :version, :seed, :unit, :encrypted_seed, :seed_encryption_method)
                """,
                {
                    "id": keyset.id,
                    "derivation_path": keyset.derivation_path,
                    "valid_from": keyset.valid_from,
                    "valid_to": keyset.valid_to,
                    "first_seen": keyset.first_seen,
                    "active": keyset.active,
                    "version": keyset.version,
                    "seed": keyset.seed,
                    "unit": keyset.unit.name,
                    "encrypted_seed": keyset.encrypted_seed,
                    "seed_encryption_method": keyset.seed_encryption_method,
                },
            )


async def m019_add_fee_to_keysets(db: Database):
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('keysets')} ADD COLUMN input_fee_ppk INTEGER"
        )
        await conn.execute(
            f"UPDATE {db.table_with_schema('keysets')} SET input_fee_ppk = 0"
        )


async def m020_add_state_to_mint_and_melt_quotes(db: Database):
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('mint_quotes')} ADD COLUMN state TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('melt_quotes')} ADD COLUMN state TEXT"
        )

    # get all melt and mint quotes and figure out the state to set using the `paid` column
    # and the `paid` and `issued` column respectively
    # mint quotes:
    async with db.connect() as conn:
        rows: List[Dict] = await conn.fetchall(
            f"SELECT * FROM {db.table_with_schema('mint_quotes')}"
        )
        for row in rows:
            if row.get("issued"):
                state = "issued"
            elif row.get("paid"):
                state = "paid"
            else:
                state = "unpaid"
            await conn.execute(
                f"UPDATE {db.table_with_schema('mint_quotes')} SET state = '{state}' WHERE quote = '{row['quote']}'"
            )

    # melt quotes:
    async with db.connect() as conn:
        rows2: List[Dict] = await conn.fetchall(
            f"SELECT * FROM {db.table_with_schema('melt_quotes')}"
        )
        for row in rows2:
            if row["paid"]:
                state = "paid"
            else:
                state = "unpaid"
            await conn.execute(
                f"UPDATE {db.table_with_schema('melt_quotes')} SET state = '{state}' WHERE quote = '{row['quote']}'"
            )


async def m021_add_change_and_expiry_to_melt_quotes(db: Database):
    async with db.connect() as conn:
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('melt_quotes')} ADD COLUMN change TEXT"
        )
        await conn.execute(
            f"ALTER TABLE {db.table_with_schema('melt_quotes')} ADD COLUMN expiry TIMESTAMP"
        )


async def m022_quote_set_states_to_values(db: Database):
    async with db.connect() as conn:
        for melt_quote_states in MeltQuoteState:
            await conn.execute(
                f"UPDATE {db.table_with_schema('melt_quotes')} SET state = '{melt_quote_states.value}' WHERE state = '{melt_quote_states.name}'"
            )
        for mint_quote_states in MintQuoteState:
            await conn.execute(
                f"UPDATE {db.table_with_schema('mint_quotes')} SET state = '{mint_quote_states.value}' WHERE state = '{mint_quote_states.name}'"
            )
