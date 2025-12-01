import argparse
import asyncio
import datetime
import os
import re
import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

# Reuse project DB and migrations to create target schema
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.mint import migrations as mint_migrations

DEFAULT_BATCH_SIZE = 1000


def _is_int_string(value: str) -> bool:
    return bool(re.fullmatch(r"\d+", value))


def _convert_value(value: Any, decl_type: Optional[str]) -> Any:
    if value is None:
        return None
    if not decl_type:
        return value
    dtype = decl_type.upper()

    if "TIMESTAMP" in dtype:
        # SQLite stores timestamps as INT seconds or formatted strings
        if isinstance(value, (int, float)):
            return datetime.datetime.fromtimestamp(int(value))
        if isinstance(value, str):
            if _is_int_string(value):
                return datetime.datetime.fromtimestamp(int(value))
            # try parse common format; fallback to raw string
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
                try:
                    return datetime.datetime.strptime(value, fmt)
                except Exception:
                    pass
            return value
        return value

    if dtype in {"BOOL", "BOOLEAN"}:
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str) and value.lower() in {"0", "1", "true", "false"}:
            return value.lower() in {"1", "true"}
        return bool(value)

    # BIGINT/INT: leave as-is; asyncpg will coerce ints
    return value


def _get_sqlite_tables(conn: sqlite3.Connection) -> List[Tuple[str, str]]:
    cur = conn.cursor()
    # exclude sqlite internal tables
    rows = cur.execute(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    return [(r[0], r[1]) for r in rows]


def _get_table_columns(
    conn: sqlite3.Connection, table: str
) -> List[Tuple[str, Optional[str]]]:
    cur = conn.cursor()
    rows = cur.execute(f"PRAGMA table_info({table})").fetchall()
    # rows: cid, name, type, notnull, dflt_value, pk
    return [(r[1], r[2]) for r in rows]


def _iter_sqlite_rows(
    conn: sqlite3.Connection, table: str, batch_size: int
) -> Iterable[List[sqlite3.Row]]:
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table}")
    while True:
        rows = cur.fetchmany(batch_size)
        if not rows:
            break
        yield rows


def _prepare_insert_sql(table: str, columns: List[str]) -> str:
    cols = ", ".join(columns)
    params = ", ".join(f":{c}" for c in columns)
    # Use ON CONFLICT DO NOTHING to make script idempotent on empty DBs
    return f"INSERT INTO {table} ({cols}) VALUES ({params}) ON CONFLICT DO NOTHING"


async def _ensure_target_schema(pg_url: str) -> Database:
    db = Database("mint", pg_url)
    await migrate_databases(db, mint_migrations)
    return db


async def _pg_table_row_count(db: Database, table: str) -> int:
    try:
        async with db.connect() as conn:
            r = await conn.fetchone(f"SELECT COUNT(*) AS c FROM {table}")
            return int(r["c"]) if r else 0
    except Exception:
        return 0


def _sqlite_table_row_count(conn: sqlite3.Connection, table: str) -> int:
    try:
        cur = conn.cursor()
        return int(cur.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    except Exception:
        return 0


async def _precheck_postgres_populated(
    pg_url: str, candidate_tables: List[str]
) -> Optional[str]:
    db = Database("mint", pg_url)
    populated: List[Tuple[str, int]] = []
    for t in candidate_tables:
        cnt = await _pg_table_row_count(db, t)
        if cnt > 0:
            populated.append((t, cnt))

    if populated:
        url = urlparse(pg_url.replace("postgresql+asyncpg://", "postgres://"))
        user = url.username or "<user>"
        host = url.hostname or "localhost"
        port = url.port or 5432
        dbname = (url.path or "/").lstrip("/") or "<database>"
        details = ", ".join(f"{t}={c}" for t, c in populated)
        info = (
            "Target Postgres database appears to be populated; aborting migration to avoid corruption.\n"
            f"Detected rows: {details}.\n"
            "To reset the database, connect as the proper user and run:\n"
            f'psql -U {user} -h {host} -p {port} -d {dbname} -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL PRIVILEGES ON SCHEMA public TO {user};"'
        )
        return info
    return None


async def _compare_balance_views(
    sqlite_conn: sqlite3.Connection, pg_db: Database
) -> Tuple[bool, str]:
    # Read SQLite balance view
    try:
        s_rows = sqlite_conn.execute("SELECT keyset, balance FROM balance").fetchall()
        sqlite_map = {str(r[0]): int(r[1]) for r in s_rows}
    except Exception as e:
        return False, f"Failed reading SQLite balance view: {e}"

    # Read Postgres balance view
    try:
        async with pg_db.connect() as conn:
            p_rows = await conn.fetchall("SELECT keyset, balance FROM balance")
        pg_map = {str(r["keyset"]): int(r["balance"]) for r in p_rows}
    except Exception as e:
        return False, f"Failed reading Postgres balance view: {e}"

    if sqlite_map == pg_map:
        return True, "Balance views match"

    # Summarize differences
    diffs = []
    keys = set(sqlite_map) | set(pg_map)
    for k in sorted(keys):
        sv = sqlite_map.get(k)
        pv = pg_map.get(k)
        if sv != pv:
            diffs.append(f"{k}: sqlite={sv} postgres={pv}")
            if len(diffs) >= 10:
                diffs.append("…")
                break
    return False, "Balance view differs: " + "; ".join(diffs)


async def _copy_table(
    sqlite_conn: sqlite3.Connection,
    pg_db: Database,
    table: str,
    batch_size: int,
) -> int:
    # views are skipped; ensure table exists on target
    columns_with_types = _get_table_columns(sqlite_conn, table)
    if not columns_with_types:
        return 0
    columns = [name for name, _ in columns_with_types]
    insert_sql = _prepare_insert_sql(table, columns)

    total = 0
    total_rows = _sqlite_table_row_count(sqlite_conn, table)
    printed_done = False
    # commit per batch to avoid gigantic transactions
    for batch in _iter_sqlite_rows(sqlite_conn, table, batch_size):
        payload: List[Dict[str, Any]] = []
        for row in batch:
            row_dict = {columns[i]: row[i] for i in range(len(columns))}
            normalized: Dict[str, Any] = {}
            for col, decl_type in columns_with_types:
                normalized[col] = _convert_value(row_dict.get(col), decl_type)
            payload.append(normalized)

        if not payload:
            continue
        async with pg_db.connect() as conn:  # new txn per batch
            await conn.execute(insert_sql, payload)
        total += len(payload)
        if total_rows:
            pct = int(total * 100 / total_rows)
            print(f"[{table}] {total}/{total_rows} ({pct}%)", end="\r", flush=True)
            printed_done = True
    if printed_done:
        print("")
    return total


def _ordered_tables(existing: Dict[str, str]) -> List[str]:
    desired_order = [
        "keysets",
        "mint_pubkeys",
        "mint_quotes",
        "melt_quotes",
        "promises",
        "proofs_used",
        "proofs_pending",
        "balance_log",
    ]
    # Filter desired order by presence
    present_ordered = [
        t for t in desired_order if t in existing and existing[t] == "table"
    ]
    # Append any other base tables not covered yet
    rest = [
        t
        for t, typ in existing.items()
        if typ == "table" and t not in present_ordered and t not in {"dbversions"}
    ]
    return present_ordered + rest


async def migrate_sqlite_to_postgres(
    sqlite_path: str, pg_url: str, batch_size: int
) -> None:
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite file not found: {sqlite_path}")

    # 1) open sqlite
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    # decide which tables to check/copy
    all_tables = _get_sqlite_tables(sqlite_conn)
    table_map = {name: typ for name, typ in all_tables}
    skip = {"dbversions", "balance", "balance_issued", "balance_redeemed"}
    candidate_tables = [
        t for t, typ in table_map.items() if typ == "table" and t not in skip
    ]

    # 2) precheck Postgres not populated
    info = await _precheck_postgres_populated(pg_url, candidate_tables)
    if info:
        print(info)
        sqlite_conn.close()
        return

    # 3) ensure target schema on postgres
    pg_db = await _ensure_target_schema(pg_url)

    # 4) inspect sqlite schema
    ordered = _ordered_tables(table_map)
    ordered = [t for t in ordered if t not in skip]

    # 5) copy data
    for tbl in ordered:
        print(f"Copying table: {tbl}")
        count = await _copy_table(sqlite_conn, pg_db, tbl, batch_size)
        print(f"Copied {count} rows from {tbl}")

    # 6) verification: compare table row counts and balance view
    print("Verifying data integrity …")
    mismatches: List[str] = []
    for tbl in ordered:
        s_cnt = _sqlite_table_row_count(sqlite_conn, tbl)
        p_cnt = await _pg_table_row_count(pg_db, tbl)
        if s_cnt != p_cnt:
            mismatches.append(f"{tbl}: sqlite={s_cnt} postgres={p_cnt}")
    ok_balance, balance_msg = await _compare_balance_views(sqlite_conn, pg_db)

    # 7) finalize
    await pg_db.engine.dispose()  # close connections cleanly
    sqlite_conn.close()

    if mismatches:
        print("WARNING: Row count mismatches detected:")
        for m in mismatches:
            print(f" - {m}")
    if not ok_balance:
        print(f"WARNING: {balance_msg}")

    if not mismatches and ok_balance:
        total_rows_copied = sum(
            _sqlite_table_row_count(sqlite3.connect(sqlite_path), t) for t in ordered
        )
        print(
            "Migration successful: all row counts match and balance view is identical.\n"
            f"Tables migrated: {len(ordered)}, total rows: {total_rows_copied}."
        )
    else:
        print("Migration completed with warnings. Review the messages above.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate Cashu mint SQLite DB to Postgres"
    )
    parser.add_argument("--sqlite", required=True, help="Path to mint.sqlite3 file")
    parser.add_argument(
        "--postgres",
        required=True,
        help="Postgres connection string, e.g. postgres://user:pass@host:5432/dbname",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Batch size for inserts (default {DEFAULT_BATCH_SIZE})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(migrate_sqlite_to_postgres(args.sqlite, args.postgres, args.batch_size))


if __name__ == "__main__":
    main()
