"""Offline audit and explicit correction of payment quote identities."""

import asyncio
import hashlib
import json
from typing import Optional

import click

from ..core.db import Database, LockOptions


async def audit(db: Database) -> dict:
    table = db.table_with_schema("mint_quotes")
    duplicates = []
    for field in ("request", "checking_id"):
        groups = await db.fetchall(
            f"SELECT method, {field} AS identity FROM {table} "
            f"WHERE {field} <> '' GROUP BY method, {field} HAVING COUNT(*) > 1"
        )
        for group in groups:
            rows = await db.fetchall(
                f"SELECT quote FROM {table} WHERE method = :method AND {field} = :identity",
                dict(group),
            )
            duplicates.append(
                {
                    "field": field,
                    "method": group["method"],
                    "quotes": [r["quote"] for r in rows],
                }
            )
    async with db.connect() as conn:
        result = await conn.execute(f"SELECT * FROM {table} LIMIT 0")
        columns = set(result.keys())
    rows = (
        await db.fetchall(f"SELECT quote FROM {table} WHERE amount_paid_internal > 0")
        if "amount_paid_internal" in columns
        else []
    )
    credits = [r["quote"] for r in rows]
    return {"duplicates": duplicates, "internal_credits_to_verify": credits}


async def repair(
    db: Database, quote: str, field: str, expected: str, replacement: str, apply: bool
) -> None:
    if field not in {"request", "checking_id"} or not replacement:
        raise ValueError("choose request or checking_id and a nonempty replacement")
    table = db.table_with_schema("mint_quotes")
    async with db.get_connection(locks=[LockOptions(table="mint_quotes")]) as conn:
        row = await conn.fetchone(
            f"SELECT * FROM {table} WHERE quote = :quote", {"quote": quote}
        )
        if not row or row[field] != expected:
            raise ValueError("quote or expected identity does not match")
        if (
            row["state"] != "UNPAID"
            or row.get("amount_paid")
            or row.get("amount_issued")
            or row.get("amount_paid_internal")
        ):
            raise ValueError(
                "funded or issued records require reconciliation with the original backend"
            )
        promises = await conn.fetchone(
            f"SELECT 1 FROM {db.table_with_schema('promises')} WHERE mint_quote = :quote LIMIT 1",
            {"quote": quote},
        )
        if promises:
            raise ValueError("quote has associated issuance records")
        duplicate = await conn.fetchone(
            f"SELECT 1 FROM {table} WHERE method = :method AND {field} = :replacement AND quote <> :quote",
            {"method": row["method"], "replacement": replacement, "quote": quote},
        )
        if duplicate:
            raise ValueError("replacement identity is already assigned")
        if apply:
            assignments = f"{field} = :replacement"
            params = {"quote": quote, "replacement": replacement}
            if f"{field}_hash" in row:
                assignments += f", {field}_hash = :digest"
                params["digest"] = hashlib.sha256(replacement.encode()).hexdigest()
            await conn.execute(
                f"UPDATE {table} SET {assignments} WHERE quote = :quote", params
            )


@click.command()
@click.option(
    "--database",
    required=True,
    envvar="MINT_DATABASE",
    help="Offline mint database directory or PostgreSQL URL.",
)
@click.option(
    "--quote",
    default=None,
    help="Quote to correct after checking its original backend.",
)
@click.option("--field", type=click.Choice(["request", "checking_id"]))
@click.option("--expected", default=None)
@click.option("--replacement", default=None)
@click.option(
    "--apply",
    is_flag=True,
    help="Apply an explicitly selected identity correction; default is dry run.",
)
def main(
    database: str,
    quote: Optional[str],
    field: Optional[str],
    expected: Optional[str],
    replacement: Optional[str],
    apply: bool,
):
    async def run():
        db = Database("mint", database)
        try:
            if quote:
                if field is None or expected is None or replacement is None:
                    raise click.UsageError(
                        "correction requires --field, --expected and --replacement"
                    )
                await repair(db, quote, field, expected, replacement, apply)
                click.echo(
                    "Correction applied." if apply else "Correction validated; dry run."
                )
            elif apply:
                raise click.UsageError("--apply requires an explicit quote correction")
            else:
                click.echo(json.dumps(await audit(db), indent=2))
        finally:
            await db.engine.dispose()

    try:
        asyncio.run(run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc


if __name__ == "__main__":
    main()
