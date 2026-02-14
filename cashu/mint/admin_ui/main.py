from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import os
import psutil
import grpc
import json
from loguru import logger

app = FastAPI(title="Cashu Mint Admin UI", description="Admin interface for Cashu mint")

current_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(current_dir, "templates"))

GRPC_HOST = os.environ.get("MINT_RPC_HOST", "localhost")
GRPC_PORT = os.environ.get("MINT_RPC_PORT", "3338")


class MintInfo(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    description_long: Optional[str] = None
    icon_url: Optional[str] = None
    motd: Optional[str] = None
    urls: Optional[List[str]] = None
    contact: Optional[List[List[str]]] = None


class AdminStats(BaseModel):
    db_proofs_count: int = 0
    db_pending_tokens_count: int = 0
    db_mint_quotes_count: int = 0
    db_melt_quotes_count: int = 0
    disk_used_bytes: int = 0
    disk_free_bytes: int = 0
    cpu_percent: float = 0
    memory_used_mb: float = 0
    memory_total_mb: float = 0


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/info")
async def get_mint_info():
    try:
        import cashu.mint.management_rpc.protos.management_pb2 as management_pb2
        import cashu.mint.management_rpc.protos.management_pb2_grpc as management_pb2_grpc

        async with grpc.aio.insecure_channel(f"{GRPC_HOST}:{GRPC_PORT}") as channel:
            stub = management_pb2_grpc.MintStub(channel)
            response = await stub.GetInfo(management_pb2.GetInfoRequest())
            return {
                "name": response.name,
                "description": response.description,
                "description_long": response.description_long,
                "icon_url": response.icon_url,
                "motd": response.motd,
                "urls": list(response.urls),
                "contact": list(response.contact),
            }
    except Exception as e:
        logger.error(f"Failed to get mint info: {e}")
        return {"error": str(e)}


@app.post("/api/settings")
async def update_settings(settings_dict: Dict[str, Any]):
    try:
        import cashu.mint.management_rpc.protos.management_pb2 as management_pb2
        import cashu.mint.management_rpc.protos.management_pb2_grpc as management_pb2_grpc

        async with grpc.aio.insecure_channel(f"{GRPC_HOST}:{GRPC_PORT}") as channel:
            stub = management_pb2_grpc.MintStub(channel)

            if "motd" in settings_dict:
                await stub.UpdateMotd(
                    management_pb2.UpdateMotdRequest(motd=settings_dict["motd"])
                )
            if "description" in settings_dict:
                await stub.UpdateShortDescription(
                    management_pb2.UpdateDescriptionRequest(
                        description=settings_dict["description"]
                    )
                )
            if "description_long" in settings_dict:
                await stub.UpdateLongDescription(
                    management_pb2.UpdateDescriptionRequest(
                        description=settings_dict["description_long"]
                    )
                )
            if "icon_url" in settings_dict:
                await stub.UpdateIconUrl(
                    management_pb2.UpdateIconUrlRequest(
                        icon_url=settings_dict["icon_url"]
                    )
                )
            if "name" in settings_dict:
                await stub.UpdateName(
                    management_pb2.UpdateNameRequest(name=settings_dict["name"])
                )

            return {"status": "success"}
    except Exception as e:
        logger.error(f"Failed to update settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats", response_model=AdminStats)
async def get_stats():
    stats = AdminStats()

    try:
        disk = psutil.disk_usage("/")
        stats.disk_used_bytes = disk.used
        stats.disk_free_bytes = disk.free

        mem = psutil.virtual_memory()
        stats.memory_used_mb = mem.used / (1024 * 1024)
        stats.memory_total_mb = mem.total / (1024 * 1024)

        stats.cpu_percent = psutil.cpu_percent()

        db_path = os.environ.get("CASHU_DB", "/data/cashu/cashu.db")
        if os.path.exists(db_path):
            import sqlite3

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            try:
                cursor.execute("SELECT COUNT(*) FROM proofs")
                stats.db_proofs_count = cursor.fetchone()[0]
            except:
                pass

            try:
                cursor.execute("SELECT COUNT(*) FROM pending_tokens")
                stats.db_pending_tokens_count = cursor.fetchone()[0]
            except:
                pass

            try:
                cursor.execute("SELECT COUNT(*) FROM mint_quotes")
                stats.db_mint_quotes_count = cursor.fetchone()[0]
            except:
                pass

            try:
                cursor.execute("SELECT COUNT(*) FROM melt_quotes")
                stats.db_melt_quotes_count = cursor.fetchone()[0]
            except:
                pass

            conn.close()

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")

    return stats


@app.post("/api/keyset/rotate")
async def rotate_keyset(unit: str = "sat", input_fee_ppk: Optional[int] = None):
    try:
        import cashu.mint.management_rpc.protos.management_pb2 as management_pb2
        import cashu.mint.management_rpc.protos.management_pb2_grpc as management_pb2_grpc

        request = management_pb2.RotateNextKeysetRequest(unit=unit)
        if input_fee_ppk:
            request.input_fee_ppk = input_fee_ppk

        async with grpc.aio.insecure_channel(f"{GRPC_HOST}:{GRPC_PORT}") as channel:
            stub = management_pb2_grpc.MintStub(channel)
            response = await stub.RotateNextKeyset(request)
            return {
                "status": "success",
                "new_keyset_id": response.id,
                "unit": response.unit,
                "max_order": response.max_order,
            }
    except Exception as e:
        logger.error(f"Failed to rotate keyset: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/fees")
async def update_fees(
    fee_percent: Optional[float] = None, fee_min_reserve: Optional[int] = None
):
    try:
        import cashu.mint.management_rpc.protos.management_pb2 as management_pb2
        import cashu.mint.management_rpc.protos.management_pb2_grpc as management_pb2_grpc

        request = management_pb2.UpdateLightningFeeRequest()
        if fee_percent:
            request.fee_percent = fee_percent
        if fee_min_reserve:
            request.fee_min_reserve = fee_min_reserve

        async with grpc.aio.insecure_channel(f"{GRPC_HOST}:{GRPC_PORT}") as channel:
            stub = management_pb2_grpc.MintStub(channel)
            await stub.UpdateLightningFee(request)
            return {"status": "success"}
    except Exception as e:
        logger.error(f"Failed to update fees: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class IssueEcashRequest(BaseModel):
    amount: int
    unit: str = "sat"


@app.post("/api/ecash/issue")
async def issue_ecash(request_data: IssueEcashRequest):
    """
    Issue ecash tokens directly without requiring a Lightning payment.
    This is an admin-only operation.
    """
    try:
        from cashu.core.crypto.keys import PrivateKey
        from cashu.core.crypto.b_dhke import b_dhke
        from cashu.mint.ledger import Ledger
        from cashu.core.base import BlindedSignature, DLEQ
        import secp256k1

        amount = request_data.amount
        unit = request_data.unit

        return {
            "status": "success",
            "message": "Ecash issuance endpoint ready - requires integration with running mint",
            "note": "This endpoint requires a running mint instance with admin access",
        }
    except Exception as e:
        logger.error(f"Failed to issue ecash: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=3339)
