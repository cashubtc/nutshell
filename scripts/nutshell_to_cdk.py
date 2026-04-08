import argparse
import logging
import os
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger("nutshell_to_cdk")

GENERATOR_POINT_HEX = (
    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)
MIN_COMPATIBLE_VERSION = (0, 15, 0)
DEFAULT_EXPIRY_OFFSET = 157784760
DEFAULT_BATCH_SIZE = 5000
MAX_WITNESS_LENGTH = 1024

CDK_REQUIRED_TABLES = [
    "keyset",
    "proof",
    "blind_signature",
    "mint_quote",
    "melt_quote",
    "keyset_amounts",
]

NUTSHELL_REQUIRED_TABLES = [
    "keysets",
    "proofs_used",
    "proofs_pending",
    "promises",
    "mint_quotes",
    "melt_quotes",
]


def detect_db_type(conn_string: str) -> str:
    lower = conn_string.lower().strip()
    if lower.startswith(("postgresql://", "postgres://", "cockroachdb://")):
        return "postgres"
    return "sqlite"


def resolve_sqlite_path(conn_string: str) -> str:
    for prefix in ("sqlite:///", "sqlite://"):
        if conn_string.lower().startswith(prefix):
            return conn_string[len(prefix) :]
    return conn_string


def resolve_pg_dsn(conn_string: str) -> str:
    s = conn_string.strip()
    if s.lower().startswith("cockroachdb://"):
        s = "postgresql://" + s[len("cockroachdb://") :]
    return s


def connect(conn_string: str, role: str) -> Tuple[Any, str]:
    db_type = detect_db_type(conn_string)

    if db_type == "sqlite":
        path = resolve_sqlite_path(conn_string)
        if not os.path.isfile(path):
            if role == "source":
                logger.error(f"Source SQLite file not found: {path}")
            else:
                logger.error(
                    f"Target SQLite file not found: {path}\n"
                    "  Run cdk-mintd once to initialize the database schema."
                )
            sys.exit(1)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=OFF")
        return conn, db_type

    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        logger.error(
            "psycopg2 is required for PostgreSQL/CockroachDB.\n"
            "  Install: pip install psycopg2-binary"
        )
        sys.exit(1)

    dsn = resolve_pg_dsn(conn_string)
    try:
        conn = psycopg2.connect(dsn, cursor_factory=psycopg2.extras.DictCursor)
        conn.autocommit = False
        return conn, db_type
    except Exception as e:
        logger.error(f"Failed to connect to {role} database: {e}")
        sys.exit(1)


def hex_to_blob(hex_string: Optional[str]) -> Optional[bytes]:
    if not hex_string:
        return None
    try:
        return bytes.fromhex(hex_string.strip().replace("0x", ""))
    except (ValueError, AttributeError):
        logger.warning(f"Failed hex->bytes: {hex_string[:40]}...")
        return None


def to_unix_seconds(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp())
    if isinstance(value, str):
        value = value.strip()
        try:
            return int(float(value))
        except ValueError:
            pass
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S%z",
        ):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return int(dt.timestamp())
            except ValueError:
                continue
    logger.warning(f"Could not parse timestamp: {value!r}, defaulting to 0")
    return 0


def parse_version(version: Optional[str]) -> Tuple[int, int, int]:
    if not version:
        return (0, 0, 0)
    try:
        parts = version.strip().split(".")
        return (int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0)
    except (ValueError, IndexError):
        return (0, 0, 0)


def parse_derivation_path(path: Optional[str]) -> Tuple[str, Optional[int]]:
    if not path:
        return ("", None)
    clean = path.strip()
    if clean.startswith("m/"):
        clean = clean[2:]
    parts = clean.split("/")
    if parts:
        try:
            return (clean, int(parts[-1].replace("'", "")))
        except ValueError:
            pass
    return (clean, None)


def truncate_witness(witness: Optional[str]) -> Optional[str]:
    if witness and len(witness) > MAX_WITNESS_LENGTH:
        return None
    return witness


def table_exists(conn: Any, db_type: str, table_name: str) -> bool:
    cur = conn.cursor()
    if db_type == "sqlite":
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
    else:
        cur.execute(
            "SELECT tablename FROM pg_tables WHERE tablename = %s",
            (table_name,),
        )
    result = cur.fetchone()
    cur.close()
    return result is not None


def count_rows(conn: Any, db_type: str, table_name: str, where: str = "") -> int:
    sql = f"SELECT COUNT(*) FROM {table_name}"
    if where:
        sql += f" WHERE {where}"
    cur = conn.cursor()
    cur.execute(sql)
    row = cur.fetchone()
    cur.close()
    return row[0] if row else 0


def ph(db_type: str) -> str:
    return "?" if db_type == "sqlite" else "%s"


def fetch_batched(
    conn: Any, sql: str, batch_size: int
) -> Generator[List[Any], None, None]:
    cur = conn.cursor()
    cur.execute(sql)
    while True:
        rows = cur.fetchmany(batch_size)
        if not rows:
            break
        yield rows
    cur.close()


def conflict_ignore(db_type: str, table: str, pk: str) -> str:
    if db_type == "sqlite":
        return "INSERT OR IGNORE"
    return "INSERT"


def conflict_suffix(db_type: str, pk: str = "") -> str:
    if db_type == "sqlite":
        return ""
    if pk:
        return f" ON CONFLICT ({pk}) DO NOTHING"
    return " ON CONFLICT DO NOTHING"


def preflight_checks(
    src_conn: Any,
    src_type: str,
    dst_conn: Any,
    dst_type: str,
) -> List[str]:
    warnings: List[str] = []

    for table in NUTSHELL_REQUIRED_TABLES:
        if not table_exists(src_conn, src_type, table):
            logger.error(
                f"Source table '{table}' not found. Is this a Nutshell mint DB?"
            )
            sys.exit(1)

    for table in CDK_REQUIRED_TABLES:
        if not table_exists(dst_conn, dst_type, table):
            logger.error(
                f"Target table '{table}' not found.\n"
                "  The CDK database schema is not initialized.\n"
                "  Run cdk-mintd once to create the schema, then retry."
            )
            sys.exit(1)

    for table in ["keyset", "proof", "blind_signature", "mint_quote", "melt_quote"]:
        n = count_rows(dst_conn, dst_type, table)
        if n > 0:
            warnings.append(
                f"Target '{table}' already has {n} rows. Duplicates will be skipped."
            )

    cur = src_conn.cursor()
    cur.execute("SELECT id, version FROM keysets")
    for row in cur.fetchall():
        r = dict(row)
        v = parse_version(r.get("version"))
        if v < MIN_COMPATIBLE_VERSION:
            warnings.append(
                f"Keyset '{r['id']}' version {r.get('version')} (< 0.15.0) "
                "will be SKIPPED — incompatible with CDK."
            )
    cur.close()

    return warnings


def migrate_keysets(
    src_conn: Any,
    src_type: str,
    dst_conn: Any,
    dst_type: str,
    batch_size: int,
) -> int:
    migrated = 0
    skipped = 0

    sql_read = (
        "SELECT id, unit, active, valid_from, valid_to, derivation_path,"
        " input_fee_ppk, version, amounts FROM keysets"
    )

    sql_write = (
        f"{conflict_ignore(dst_type, 'keyset', 'id')} INTO keyset"
        " (id, unit, active, valid_from, valid_to, derivation_path,"
        " derivation_path_index, input_fee_ppk, issuer_version, amounts)"
        f" VALUES ({', '.join([ph(dst_type)] * 10)})"
        f"{conflict_suffix(dst_type, 'id')}"
    )

    for batch in fetch_batched(src_conn, sql_read, batch_size):
        rows_to_insert = []
        for row in batch:
            r = dict(row)
            version = r.get("version", "")
            if parse_version(version) < MIN_COMPATIBLE_VERSION:
                skipped += 1
                continue

            base_path, path_index = parse_derivation_path(r.get("derivation_path"))
            issuer_version = f"nutshell/{version}" if version else None

            rows_to_insert.append(
                (
                    r["id"],
                    r.get("unit") or "sat",
                    bool(r.get("active", False)),
                    to_unix_seconds(r.get("valid_from")),
                    to_unix_seconds(r.get("valid_to")) if r.get("valid_to") else None,
                    base_path,
                    path_index,
                    r.get("input_fee_ppk") or 0,
                    issuer_version,
                    r.get("amounts"),
                )
            )

        if rows_to_insert:
            cur = dst_conn.cursor()
            cur.executemany(sql_write, rows_to_insert)
            migrated += len(rows_to_insert)
            cur.close()

    if skipped:
        logger.warning(f"Skipped {skipped} keysets with version < 0.15.0")

    dst_conn.commit()
    logger.info(f"Keysets migrated: {migrated}")
    return migrated


def migrate_proofs(
    src_conn: Any,
    src_type: str,
    dst_conn: Any,
    dst_type: str,
    batch_size: int,
    melt_quote_ops: Dict[str, str],
) -> Tuple[int, int]:
    sql_write = (
        f"{conflict_ignore(dst_type, 'proof', 'y')} INTO proof"
        " (y, amount, keyset_id, secret, c, witness, state,"
        " quote_id, created_time, operation_kind, operation_id)"
        f" VALUES ({', '.join([ph(dst_type)] * 11)})"
        f"{conflict_suffix(dst_type, 'y')}"
    )

    def _process_row(r: Dict[str, Any], state: str, link_ops: bool) -> Tuple[Any, ...]:
        y_blob = hex_to_blob(r.get("y"))
        if not y_blob:
            y_blob = secrets.token_bytes(33)
        c_blob = hex_to_blob(r.get("c"))
        if not c_blob:
            c_blob = bytes.fromhex(GENERATOR_POINT_HEX)

        melt_q = r.get("melt_quote")
        op_id = melt_quote_ops.get(melt_q) if (link_ops and melt_q) else None
        op_kind = "melt" if op_id else None

        return (
            y_blob,
            r.get("amount", 0),
            r.get("id", ""),
            r.get("secret", ""),
            c_blob,
            truncate_witness(r.get("witness")),
            state,
            melt_q,
            to_unix_seconds(r.get("created")),
            op_kind,
            op_id,
        )

    spent_count = 0
    for batch in fetch_batched(
        src_conn,
        "SELECT y, amount, id, secret, c, witness, created, melt_quote FROM proofs_used",
        batch_size,
    ):
        rows = [_process_row(dict(row), "SPENT", False) for row in batch]
        if rows:
            cur = dst_conn.cursor()
            cur.executemany(sql_write, rows)
            spent_count += len(rows)
            cur.close()
    dst_conn.commit()

    pending_count = 0
    for batch in fetch_batched(
        src_conn,
        "SELECT y, amount, id, secret, c, witness, created, melt_quote FROM proofs_pending",
        batch_size,
    ):
        rows = [_process_row(dict(row), "PENDING", True) for row in batch]
        if rows:
            cur = dst_conn.cursor()
            cur.executemany(sql_write, rows)
            pending_count += len(rows)
            cur.close()
    dst_conn.commit()

    logger.info(f"Proofs migrated: {spent_count} spent, {pending_count} pending")
    return spent_count, pending_count


def migrate_blind_signatures(
    src_conn: Any,
    src_type: str,
    dst_conn: Any,
    dst_type: str,
    batch_size: int,
) -> int:
    sql_write = (
        f"{conflict_ignore(dst_type, 'blind_signature', 'blinded_message')}"
        " INTO blind_signature"
        " (blinded_message, amount, keyset_id, c, dleq_e, dleq_s,"
        " quote_id, created_time, signed_time, operation_kind, operation_id)"
        f" VALUES ({', '.join([ph(dst_type)] * 11)})"
        f"{conflict_suffix(dst_type, 'blinded_message')}"
    )

    sql_read = (
        "SELECT b_, amount, id, c_, dleq_e, dleq_s, mint_quote, melt_quote,"
        " created, signed_at, swap_id FROM promises"
    )

    count = 0
    for batch in fetch_batched(src_conn, sql_read, batch_size):
        rows = []
        for row in batch:
            r = dict(row)
            b_blob = hex_to_blob(r.get("b_"))
            if not b_blob:
                continue

            c_blob = hex_to_blob(r.get("c_"))
            created = to_unix_seconds(r.get("created"))
            signed = to_unix_seconds(r.get("signed_at")) if r.get("signed_at") else None
            quote_id = r.get("mint_quote") or r.get("melt_quote")

            rows.append(
                (
                    b_blob,
                    r.get("amount", 0),
                    r.get("id", ""),
                    c_blob,
                    r.get("dleq_e"),
                    r.get("dleq_s"),
                    quote_id,
                    created,
                    signed,
                    None,
                    None,
                )
            )
        if rows:
            cur = dst_conn.cursor()
            cur.executemany(sql_write, rows)
            count += len(rows)
            cur.close()
    dst_conn.commit()

    logger.info(f"Blind signatures migrated: {count}")
    return count


def migrate_mint_quotes(
    src_conn: Any,
    src_type: str,
    dst_conn: Any,
    dst_type: str,
    batch_size: int,
) -> int:
    p = ph(dst_type)

    sql_quote = (
        f"{conflict_ignore(dst_type, 'mint_quote', 'id')} INTO mint_quote"
        " (id, amount, unit, request, expiry, request_lookup_id,"
        " request_lookup_id_kind, pubkey, created_time, amount_paid,"
        " amount_issued, payment_method, extra_json)"
        f" VALUES ({', '.join([p] * 13)})"
        f"{conflict_suffix(dst_type, 'id')}"
    )

    sql_payment = (
        f"{conflict_ignore(dst_type, 'mint_quote_payments', 'payment_id')}"
        " INTO mint_quote_payments (quote_id, payment_id, timestamp, amount)"
        f" VALUES ({', '.join([p] * 4)})"
        f"{conflict_suffix(dst_type, 'payment_id')}"
    )

    sql_issued = (
        f"{conflict_ignore(dst_type, 'mint_quote_issued', 'quote_id')}"
        " INTO mint_quote_issued (quote_id, amount, timestamp)"
        f" VALUES ({', '.join([p] * 3)})"
    )
    if dst_type != "sqlite":
        sql_issued += " ON CONFLICT DO NOTHING"

    sql_read = (
        "SELECT quote, amount, unit, request, checking_id, state,"
        " created_time, paid_time, method, pubkey FROM mint_quotes"
    )

    count = 0
    for batch in fetch_batched(src_conn, sql_read, batch_size):
        quote_rows = []
        payment_rows = []
        issued_rows = []

        for row in batch:
            r = dict(row)
            state = (r.get("state") or "").upper()
            created = to_unix_seconds(r.get("created_time"))
            paid_time = (
                to_unix_seconds(r.get("paid_time")) if r.get("paid_time") else created
            )
            amount = r.get("amount", 0)
            pubkey = r.get("pubkey") or None
            if pubkey == "":
                pubkey = None

            amount_paid = amount if state in ("PAID", "ISSUED") else 0
            amount_issued = amount if state == "ISSUED" else 0
            method = (r.get("method") or "bolt11").upper()
            expiry = created + DEFAULT_EXPIRY_OFFSET

            quote_rows.append(
                (
                    r["quote"],
                    amount,
                    r.get("unit") or "sat",
                    r.get("request") or "",
                    expiry,
                    r.get("checking_id") or "",
                    "payment_hash",
                    pubkey,
                    created,
                    amount_paid,
                    amount_issued,
                    method,
                    None,
                )
            )

            if state in ("PAID", "ISSUED") and r.get("checking_id"):
                payment_rows.append(
                    (
                        r["quote"],
                        r["checking_id"],
                        paid_time,
                        amount,
                    )
                )

            if state == "ISSUED":
                issued_rows.append(
                    (
                        r["quote"],
                        amount,
                        paid_time,
                    )
                )

        cur = dst_conn.cursor()
        if quote_rows:
            cur.executemany(sql_quote, quote_rows)
            count += len(quote_rows)
        if payment_rows:
            cur.executemany(sql_payment, payment_rows)
        if issued_rows:
            cur.executemany(sql_issued, issued_rows)
        cur.close()

    dst_conn.commit()
    logger.info(f"Mint quotes migrated: {count}")
    return count


def migrate_melt_quotes(
    src_conn: Any,
    src_type: str,
    dst_conn: Any,
    dst_type: str,
    batch_size: int,
) -> Tuple[int, Dict[str, str]]:
    melt_quote_ops: Dict[str, str] = {}
    p = ph(dst_type)

    sql_quote = (
        f"{conflict_ignore(dst_type, 'melt_quote', 'id')} INTO melt_quote"
        " (id, unit, amount, request, fee_reserve, expiry, state,"
        " payment_preimage, request_lookup_id, request_lookup_id_kind,"
        " created_time, paid_time, payment_method, options)"
        f" VALUES ({', '.join([p] * 14)})"
        f"{conflict_suffix(dst_type)}"
    )

    sql_saga = (
        f"{conflict_ignore(dst_type, 'saga_state', 'operation_id')}"
        " INTO saga_state"
        " (operation_id, operation_kind, state, quote_id, created_at, updated_at)"
        f" VALUES ({', '.join([p] * 6)})"
        f"{conflict_suffix(dst_type, 'operation_id')}"
    )

    sql_read = (
        "SELECT quote, unit, amount, request, fee_reserve, state,"
        " created_time, paid_time, method, proof, checking_id, fee_paid"
        " FROM melt_quotes"
    )

    count = 0
    for batch in fetch_batched(src_conn, sql_read, batch_size):
        quote_rows = []
        saga_rows = []

        for row in batch:
            r = dict(row)
            state = (r.get("state") or "UNPAID").upper()
            created = to_unix_seconds(r.get("created_time"))
            paid_time = (
                to_unix_seconds(r.get("paid_time")) if r.get("paid_time") else None
            )
            method = (r.get("method") or "bolt11").upper()
            expiry = created + DEFAULT_EXPIRY_OFFSET
            quote_id = r["quote"]

            quote_rows.append(
                (
                    quote_id,
                    r.get("unit") or "sat",
                    r.get("amount", 0),
                    r.get("request") or "",
                    r.get("fee_reserve") or 0,
                    expiry,
                    state,
                    r.get("proof"),
                    r.get("checking_id") or "",
                    "payment_hash",
                    created,
                    paid_time,
                    method,
                    None,
                )
            )

            if state in ("UNPAID", "PENDING"):
                op_id = str(uuid.uuid4())
                now = int(datetime.now(timezone.utc).timestamp())
                saga_state = (
                    "payment_attempted" if state == "PENDING" else "setup_complete"
                )
                saga_rows.append((op_id, "melt", saga_state, quote_id, now, now))
                melt_quote_ops[quote_id] = op_id

        cur = dst_conn.cursor()
        if quote_rows:
            cur.executemany(sql_quote, quote_rows)
            count += len(quote_rows)
        if saga_rows:
            cur.executemany(sql_saga, saga_rows)
        cur.close()

    dst_conn.commit()
    logger.info(f"Melt quotes migrated: {count}")
    return count, melt_quote_ops


def populate_keyset_amounts(dst_conn: Any, dst_type: str) -> int:
    sql_calc = (
        "SELECT k.id AS keyset_id,"
        " COALESCE(bs.total_issued, 0) AS total_issued,"
        " COALESCE(sp.total_redeemed, 0) AS total_redeemed"
        " FROM keyset k"
        " LEFT JOIN ("
        "   SELECT keyset_id, SUM(amount) AS total_issued"
        "   FROM blind_signature WHERE c IS NOT NULL GROUP BY keyset_id"
        " ) bs ON k.id = bs.keyset_id"
        " LEFT JOIN ("
        "   SELECT keyset_id, SUM(amount) AS total_redeemed"
        "   FROM proof WHERE state = 'SPENT' GROUP BY keyset_id"
        " ) sp ON k.id = sp.keyset_id"
    )

    p = ph(dst_type)
    if dst_type == "sqlite":
        sql_write = (
            "INSERT OR REPLACE INTO keyset_amounts"
            f" (keyset_id, total_issued, total_redeemed, fee_collected)"
            f" VALUES ({', '.join([p] * 4)})"
        )
    else:
        sql_write = (
            "INSERT INTO keyset_amounts"
            " (keyset_id, total_issued, total_redeemed, fee_collected)"
            f" VALUES ({', '.join([p] * 4)})"
            " ON CONFLICT (keyset_id) DO UPDATE SET"
            " total_issued = EXCLUDED.total_issued,"
            " total_redeemed = EXCLUDED.total_redeemed"
        )

    cur = dst_conn.cursor()
    cur.execute(sql_calc)
    rows = cur.fetchall()

    insert_rows = []
    for row in rows:
        r = dict(row)
        insert_rows.append(
            (
                r["keyset_id"],
                r["total_issued"],
                r["total_redeemed"],
                0,
            )
        )

    if insert_rows:
        cur.executemany(sql_write, insert_rows)
    cur.close()
    dst_conn.commit()

    logger.info(f"Keyset amounts populated: {len(insert_rows)}")
    return len(insert_rows)


def verify_migration(
    src_conn: Any,
    src_type: str,
    dst_conn: Any,
    dst_type: str,
    sample_size: int = 10,
) -> bool:
    checks = [
        ("Keysets", "keysets", "keyset", None, None),
        ("Spent Proofs", "proofs_used", "proof", None, "state = 'SPENT'"),
        ("Pending Proofs", "proofs_pending", "proof", None, "state = 'PENDING'"),
        ("Blind Signatures", "promises", "blind_signature", None, None),
        ("Mint Quotes", "mint_quotes", "mint_quote", None, None),
        ("Melt Quotes", "melt_quotes", "melt_quote", None, None),
    ]

    print("\n" + "=" * 78)
    print("Migration Verification Results")
    print("=" * 78)
    print(f"{'Type':<25} {'Nutshell':>12} {'CDK':>12} {'Status':>10}")
    print("-" * 78)

    all_pass = True
    for label, src_table, dst_table, src_where, dst_where in checks:
        if src_table == "keysets":
            cur = src_conn.cursor()
            cur.execute("SELECT version FROM keysets")
            src_count = sum(
                1
                for r in cur.fetchall()
                if parse_version(dict(r).get("version")) >= MIN_COMPATIBLE_VERSION
            )
            cur.close()
        else:
            src_count = count_rows(src_conn, src_type, src_table, src_where or "")

        dst_count = count_rows(dst_conn, dst_type, dst_table, dst_where or "")

        if dst_count >= src_count:
            status = "PASS" if dst_count == src_count else "PASS*"
        else:
            status = "FAIL"
            all_pass = False

        print(f"{label:<25} {src_count:>12,} {dst_count:>12,} {status:>10}")

    print("-" * 78)
    print(f"\nSample verification (up to {sample_size} records per type):")

    verified, mismatched = _verify_proofs_sample(
        src_conn, dst_conn, dst_type, sample_size
    )
    if verified + mismatched > 0:
        print(f"  Spent proofs: {verified} ok, {mismatched} mismatched")

    verified, mismatched = _verify_mint_quotes_sample(
        src_conn, dst_conn, dst_type, sample_size
    )
    if verified + mismatched > 0:
        print(f"  Mint quotes:  {verified} ok, {mismatched} mismatched")

    overall = "ALL VERIFIED" if all_pass else "ISSUES FOUND"
    print(f"\n{'=' * 78}")
    print(f"Overall: {overall}")
    print(f"{'=' * 78}\n")
    return all_pass


def _verify_proofs_sample(
    src_conn: Any, dst_conn: Any, dst_type: str, sample_size: int
) -> Tuple[int, int]:
    cur = src_conn.cursor()
    cur.execute(f"SELECT y, amount, secret FROM proofs_used LIMIT {sample_size}")
    src_proofs = cur.fetchall()
    cur.close()

    verified = 0
    mismatched = 0
    for sp in src_proofs:
        r = dict(sp)
        y_blob = hex_to_blob(r.get("y", ""))
        if not y_blob:
            continue
        cur = dst_conn.cursor()
        cur.execute(
            f"SELECT amount, secret FROM proof WHERE y = {ph(dst_type)}", (y_blob,)
        )
        dst_row = cur.fetchone()
        cur.close()
        if dst_row:
            d = dict(dst_row)
            if d["amount"] == r["amount"] and d["secret"] == r["secret"]:
                verified += 1
            else:
                mismatched += 1
        else:
            mismatched += 1
    return verified, mismatched


def _verify_mint_quotes_sample(
    src_conn: Any, dst_conn: Any, dst_type: str, sample_size: int
) -> Tuple[int, int]:
    cur = src_conn.cursor()
    cur.execute(f"SELECT quote, amount, request FROM mint_quotes LIMIT {sample_size}")
    src_quotes = cur.fetchall()
    cur.close()

    verified = 0
    mismatched = 0
    for sq in src_quotes:
        r = dict(sq)
        cur = dst_conn.cursor()
        cur.execute(
            f"SELECT amount, request FROM mint_quote WHERE id = {ph(dst_type)}",
            (r["quote"],),
        )
        dst_row = cur.fetchone()
        cur.close()
        if dst_row:
            d = dict(dst_row)
            if d["amount"] == r["amount"] and d["request"] == r["request"]:
                verified += 1
            else:
                mismatched += 1
        else:
            mismatched += 1
    return verified, mismatched


def main():
    parser = argparse.ArgumentParser(
        description="Migrate Nutshell 0.20.0 mint database to CDK 0.16.0 mintd",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s /path/to/nutshell.sqlite /path/to/cdk.sqlite\n"
            '  %(prog)s "postgresql://u:p@host/nutshell" "postgresql://u:p@host/cdk"\n'
            '  %(prog)s "cockroachdb://u:p@host/nutshell" /path/to/cdk.sqlite\n'
            "  %(prog)s source.sqlite target.sqlite --verify-only\n"
        ),
    )
    parser.add_argument(
        "source", help="Nutshell database (file path or connection URL)"
    )
    parser.add_argument("target", help="CDK database (file path or connection URL)")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify an existing migration, do not migrate data",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Rows per batch (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    src_type = detect_db_type(args.source)
    dst_type = detect_db_type(args.target)
    logger.info(f"Source: {src_type} | Target: {dst_type}")

    src_conn, src_type = connect(args.source, "source")
    dst_conn, dst_type = connect(args.target, "target")

    if args.verify_only:
        success = verify_migration(src_conn, src_type, dst_conn, dst_type)
        src_conn.close()
        dst_conn.close()
        sys.exit(0 if success else 1)

    warnings = preflight_checks(src_conn, src_type, dst_conn, dst_type)

    print("\n" + "=" * 78)
    print("  Nutshell -> CDK Migration")
    print("  Nutshell 0.20.0 -> CDK 0.16.0")
    print("=" * 78)
    print(f"\n  Source: {args.source} ({src_type})")
    print(f"  Target: {args.target} ({dst_type})")
    print(f"  Batch size: {args.batch_size}")

    if warnings:
        print(f"\n  Warnings ({len(warnings)}):")
        for w in warnings:
            print(f"    - {w}")

    print("\n  IMPORTANT:")
    print("    - Ensure your Nutshell MINT_PRIVATE_KEY is set as the CDK seed")
    print("    - Back up both databases before proceeding")
    print("    - The CDK database schema must already be initialized\n")

    if not args.force:
        try:
            answer = input("  Proceed with migration? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("y", "yes"):
            print("  Migration cancelled.")
            src_conn.close()
            dst_conn.close()
            sys.exit(0)

    print()

    logger.info("Step 1/6: Migrating melt quotes...")
    melt_count, melt_quote_ops = migrate_melt_quotes(
        src_conn, src_type, dst_conn, dst_type, args.batch_size
    )

    logger.info("Step 2/6: Migrating keysets...")
    keyset_count = migrate_keysets(
        src_conn, src_type, dst_conn, dst_type, args.batch_size
    )

    logger.info("Step 3/6: Migrating proofs...")
    spent_count, pending_count = migrate_proofs(
        src_conn, src_type, dst_conn, dst_type, args.batch_size, melt_quote_ops
    )

    logger.info("Step 4/6: Migrating blind signatures...")
    bs_count = migrate_blind_signatures(
        src_conn, src_type, dst_conn, dst_type, args.batch_size
    )

    logger.info("Step 5/6: Migrating mint quotes...")
    mint_q_count = migrate_mint_quotes(
        src_conn, src_type, dst_conn, dst_type, args.batch_size
    )

    logger.info("Step 6/6: Populating keyset amounts...")
    ka_count = populate_keyset_amounts(dst_conn, dst_type)

    print("\n" + "=" * 78)
    print("  Migration Summary")
    print("=" * 78)
    print(f"  Keysets:           {keyset_count:>10,}")
    print(f"  Spent proofs:      {spent_count:>10,}")
    print(f"  Pending proofs:    {pending_count:>10,}")
    print(f"  Blind signatures:  {bs_count:>10,}")
    print(f"  Mint quotes:       {mint_q_count:>10,}")
    print(f"  Melt quotes:       {melt_count:>10,}")
    print(f"  Keyset amounts:    {ka_count:>10,}")
    print("=" * 78)

    if not args.force:
        try:
            answer = input("\n  Run verification? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "y"
        if answer not in ("n", "no"):
            verify_migration(src_conn, src_type, dst_conn, dst_type)
    else:
        verify_migration(src_conn, src_type, dst_conn, dst_type)

    src_conn.close()
    dst_conn.close()
    logger.info("Done.")


if __name__ == "__main__":
    main()
