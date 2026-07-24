import datetime
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..core.base import Proof
from ..core.crypto import b_dhke
from ..core.crypto.secp import PrivateKey, PublicKey
from ..core.db import Connection, Database
from ..core.errors import NotAllowedError, TransactionError
from .crud import LedgerCrud


@dataclass(frozen=True)
class PanicState:
    enabled: bool
    revision: int
    reason: Optional[str] = None


@dataclass(frozen=True)
class PanicBlacklistPreview:
    selector_id: str
    issued_from: int
    issued_until: int
    promises: List[Dict[str, Any]]

    @property
    def total_amount(self) -> int:
        return sum(int(p["amount"]) for p in self.promises)


def _unix_timestamp(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime.datetime):
        dt = value
    else:
        text = str(value)
        if text.isdigit():
            return int(text)
        try:
            dt = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp())


def _operation(row: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    if row.get("mint_quote"):
        return "MINT", str(row["mint_quote"])
    if row.get("swap_id"):
        return "SWAP", str(row["swap_id"])
    if row.get("melt_quote"):
        return "MELT_CHANGE", str(row["melt_quote"])
    return "UNKNOWN", None


class PanicService:
    def __init__(self, db: Database, crud: LedgerCrud):
        self.db = db
        self.crud = crud

    async def get_state(
        self, *, conn: Optional[Connection] = None, lock: bool = False
    ) -> PanicState:
        row = await self.crud.get_panic_state(
            db=self.db, conn=conn, lock=lock
        )
        if row is None:
            # Missing state after migrations is unsafe.
            raise RuntimeError("panic state is unavailable")
        return PanicState(
            enabled=bool(row["enabled"]),
            revision=int(row["revision"]),
            reason=row.get("reason"),
        )

    async def set_state(
        self, *, enabled: bool, reason: str, updated_by: str = ""
    ) -> PanicState:
        if not reason.strip():
            raise ValueError("a reason is required when changing panic mode")
        now = int(time.time())
        await self.crud.update_panic_state(
            db=self.db,
            enabled=enabled,
            reason=reason.strip(),
            updated_at=now,
            updated_by=updated_by,
        )
        return await self.get_state()

    async def assert_normal_operation(self, operation: str) -> None:
        if (await self.get_state()).enabled:
            raise NotAllowedError(
                f"{operation} is disabled while the mint is in panic mode."
            )

    async def preview_selector(
        self,
        *,
        issued_from: int,
        issued_until: int,
        reason: str,
        created_by: str = "",
        selector_id: Optional[str] = None,
    ) -> PanicBlacklistPreview:
        if issued_from < 0 or issued_until <= issued_from:
            raise ValueError("issued_until must be greater than issued_from")
        if not reason.strip():
            raise ValueError("a blacklist reason is required")

        serialised = await self.crud.get_panic_signed_promises(db=self.db)
        matched_operations = set()
        directly_matched = set()
        for row in serialised:
            issued_at = _unix_timestamp(row.get("signed_at")) or _unix_timestamp(
                row.get("created")
            )
            if issued_at is None or not (issued_from <= issued_at < issued_until):
                continue
            operation = _operation(row)
            if operation[1] is None:
                directly_matched.add(str(row["b_"]))
            else:
                matched_operations.add(operation)

        promises: List[Dict[str, Any]] = []
        for row in serialised:
            operation_type, operation_id = _operation(row)
            if (
                (operation_type, operation_id) not in matched_operations
                and str(row["b_"]) not in directly_matched
            ):
                continue
            promises.append(
                {
                    "b_": str(row["b_"]),
                    "amount": int(row["amount"]),
                    "keyset_id": str(row["id"]),
                    "operation_type": operation_type,
                    "operation_id": operation_id,
                    "created": _unix_timestamp(row.get("created")),
                    "signed_at": _unix_timestamp(row.get("signed_at")),
                }
            )

        resolved_id = selector_id or secrets.token_hex(16)
        return PanicBlacklistPreview(
            selector_id=resolved_id,
            issued_from=issued_from,
            issued_until=issued_until,
            promises=promises,
        )

    async def commit_selector(
        self,
        preview: PanicBlacklistPreview,
        *,
        reason: str,
        created_by: str = "",
    ) -> int:
        now = int(time.time())
        await self.crud.store_panic_blacklist(
            db=self.db,
            selector={
                "selector_id": preview.selector_id,
                "selector_kind": "TIME_RANGE",
                "issued_from": preview.issued_from,
                "issued_until": preview.issued_until,
                "reason": reason,
                "created_at": now,
                "created_by": created_by,
                "committed_at": now,
            },
            promises=[
                {
                    "b_": promise["b_"],
                    "selector_id": preview.selector_id,
                    "operation_type": promise["operation_type"],
                    "operation_id": promise["operation_id"],
                    "created_at": now,
                }
                for promise in preview.promises
            ],
        )
        return len(preview.promises)

    async def selector_exists(self, selector_id: str) -> bool:
        return await self.crud.panic_selector_exists(
            db=self.db, selector_id=selector_id
        )

    async def blacklist_blinded_messages(
        self,
        b_values: List[str],
        *,
        reason: str,
        created_by: str = "",
        selector_id: Optional[str] = None,
    ) -> int:
        if not b_values:
            raise ValueError("at least one blinded message is required")
        if not reason.strip():
            raise ValueError("a blacklist reason is required")
        canonical = []
        for value in b_values:
            try:
                # Parsing and formatting rejects malformed/non-canonical points.
                canonical.append(PublicKey(bytes.fromhex(value)).format().hex())
            except Exception as exc:
                raise ValueError("invalid blinded message") from exc
        rows = await self.crud.get_panic_signed_promises(
            db=self.db, b_s=canonical
        )
        found = {str(row["b_"]): row for row in rows}
        missing = set(canonical) - set(found)
        if missing:
            raise ValueError("blinded message was not found among issued promises")

        resolved_selector_id = selector_id or secrets.token_hex(16)
        if await self.selector_exists(resolved_selector_id):
            return 0
        now = int(time.time())
        blacklist_promises = []
        for b_ in canonical:
            operation_type, operation_id = _operation(found[b_])
            blacklist_promises.append(
                {
                    "b_": b_,
                    "selector_id": resolved_selector_id,
                    "operation_type": operation_type,
                    "operation_id": operation_id,
                    "created_at": now,
                }
            )
        await self.crud.store_panic_blacklist(
            db=self.db,
            selector={
                "selector_id": resolved_selector_id,
                "selector_kind": "BLINDED_MESSAGE",
                "issued_from": None,
                "issued_until": None,
                "reason": reason,
                "created_at": now,
                "created_by": created_by,
                "committed_at": now,
            },
            promises=blacklist_promises,
        )
        return len(canonical)

    async def verify_melt_inputs(
        self,
        proofs: List[Proof],
        *,
        conn: Optional[Connection] = None,
        lock_state: bool = False,
    ) -> None:
        if not (await self.get_state(conn=conn, lock=lock_state)).enabled:
            return
        recomputed: List[Tuple[Proof, str]] = []
        for proof in proofs:
            if not proof.dleq:
                raise TransactionError(
                    "panic mode requires DLEQ data for every input"
                )
            try:
                r = PrivateKey(bytes.fromhex(proof.dleq.r))
                B_, _ = b_dhke.step1_alice(proof.secret, r)
            except Exception as exc:
                raise TransactionError("invalid panic-mode blinding factor") from exc
            recomputed.append((proof, B_.format().hex()))

        b_values = [b_ for _, b_ in recomputed]
        rows = await self.crud.get_panic_issued_promises(
            db=self.db, b_s=b_values, conn=conn
        )
        issued = {
            (str(row["b_"]), str(row["id"]), int(row["amount"])): bool(
                row["blacklisted"]
            )
            for row in rows
        }
        for proof, b_ in recomputed:
            key = (b_, proof.id, proof.amount)
            if key not in issued or issued[key]:
                raise TransactionError(
                    "panic-mode input was not eligible for redemption"
                )
