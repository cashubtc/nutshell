import os
import shutil
import time
from hmac import compare_digest
from typing import Any, Dict

from fastapi import Header

from ..core.errors import CashuError
from ..core.settings import settings
from .startup import ledger


class MintAdminAuthError(CashuError):
    code = 20001


def _row_count_query(table: str) -> str:
    return f"SELECT COUNT(*) as c FROM {ledger.db.table_with_schema(table)}"


async def get_admin_monitor_snapshot() -> Dict[str, Any]:
    since_24h = ledger.db.timestamp_from_seconds(time.time() - 24 * 60 * 60)

    promises = await ledger.db.fetchone(_row_count_query("promises"))
    proofs_used = await ledger.db.fetchone(_row_count_query("proofs_used"))
    proofs_pending = await ledger.db.fetchone(_row_count_query("proofs_pending"))
    mint_quotes = await ledger.db.fetchone(_row_count_query("mint_quotes"))
    melt_quotes = await ledger.db.fetchone(_row_count_query("melt_quotes"))

    mint_quotes_last_24h = await ledger.db.fetchone(
        f"SELECT COUNT(*) as c FROM {ledger.db.table_with_schema('mint_quotes')} WHERE created_time >= :since",
        {"since": since_24h},
    )
    melt_quotes_last_24h = await ledger.db.fetchone(
        f"SELECT COUNT(*) as c FROM {ledger.db.table_with_schema('melt_quotes')} WHERE created_time >= :since",
        {"since": since_24h},
    )

    disk = shutil.disk_usage(settings.cashu_dir)
    load_1m = load_5m = load_15m = None
    if hasattr(os, "getloadavg"):
        load_1m, load_5m, load_15m = os.getloadavg()

    return {
        "db": {
            "promises": int(promises["c"]),
            "proofs_used": int(proofs_used["c"]),
            "proofs_pending": int(proofs_pending["c"]),
            "mint_quotes": int(mint_quotes["c"]),
            "melt_quotes": int(melt_quotes["c"]),
        },
        "requests": {
            "mint_quotes_last_24h": int(mint_quotes_last_24h["c"]),
            "melt_quotes_last_24h": int(melt_quotes_last_24h["c"]),
        },
        "host": {
            "disk_total_bytes": disk.total,
            "disk_free_bytes": disk.free,
            "cpu_load_1m": load_1m,
            "cpu_load_5m": load_5m,
            "cpu_load_15m": load_15m,
            "process_cpu_seconds": time.process_time(),
        },
    }


def require_admin_key(x_admin_key: str | None = Header(default=None)) -> None:
    configured_key = settings.mint_admin_api_key
    if not configured_key:
        raise MintAdminAuthError("admin endpoint disabled")
    if not x_admin_key or not compare_digest(x_admin_key, configured_key):
        raise MintAdminAuthError("invalid admin api key")
