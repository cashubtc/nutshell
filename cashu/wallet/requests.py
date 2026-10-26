from typing import Any, Literal

from pydantic import BaseModel, Field

from ..core.base import BlindedMessage, BlindedSignature, Proof
from ..core.db import Connection, Database


class PendingRequest(BaseModel):
    kind: Literal["swap", "melt"]
    operation: str
    inputs: list[Proof]
    outputs: list[BlindedMessage]
    secrets: list[str]
    rs: list[str]
    derivation_paths: list[str]
    keep_count: int = 0
    parameters: dict[str, Any] = Field(default_factory=dict)
    signatures: list[BlindedSignature] | None = None
    seen_pending: bool = False
    attempts: int = 0
    reserved_inputs: list[str] = Field(default_factory=list)


async def get_pending_request(
    db: Database, mint: str, operation: str, conn: Connection | None = None
) -> PendingRequest | None:
    row = await (conn or db).fetchone(
        "SELECT data FROM pending_requests WHERE mint = :mint AND operation = :operation",
        {"mint": mint, "operation": operation},
    )
    return PendingRequest.model_validate_json(row["data"]) if row else None


async def store_pending_request(
    db: Database, mint: str, request: PendingRequest, conn: Connection | None = None
) -> None:
    await (conn or db).execute(
        """
        INSERT INTO pending_requests (mint, operation, data)
        VALUES (:mint, :operation, :data)
        ON CONFLICT (mint, operation) DO NOTHING
        """,
        {
            "mint": mint,
            "operation": request.operation,
            "data": request.model_dump_json(),
        },
    )


async def update_pending_request(
    db: Database, mint: str, request: PendingRequest
) -> None:
    await db.execute(
        "UPDATE pending_requests SET data = :data WHERE mint = :mint AND operation = :operation",
        {
            "mint": mint,
            "operation": request.operation,
            "data": request.model_dump_json(),
        },
    )


async def delete_pending_request(
    db: Database, mint: str, operation: str, conn: Connection | None = None
) -> None:
    await (conn or db).execute(
        "DELETE FROM pending_requests WHERE mint = :mint AND operation = :operation",
        {"mint": mint, "operation": operation},
    )
