"""Nutshell Mint Admin UI — a separate web dashboard for managing a Cashu mint.

Communicates with the mint via its gRPC management interface and REST API.
"""

import asyncio
import base64
import logging
import platform
import secrets
from datetime import datetime, timezone
from pathlib import Path

import grpc
import httpx
from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from cashu.mint.management_rpc.protos import management_pb2, management_pb2_grpc

logger = logging.getLogger("nutshell.admin")

ADMIN_DIR = Path(__file__).parent
TEMPLATES_DIR = ADMIN_DIR / "templates"

VALID_MINT_QUOTE_STATES = {"PENDING", "UNPAID", "PAID", "ISSUED"}
VALID_MELT_QUOTE_STATES = {"PENDING", "UNPAID", "PAID"}


def _format_timestamp(value) -> str:
    """Format a Unix timestamp or datetime for display."""
    if not value:
        return "—"
    try:
        ts = int(value)
        if ts == 0:
            return "—"
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OSError):
        return str(value)


def _get_system_info() -> dict:
    """Collect basic system info without requiring psutil."""
    info: dict = {
        "platform": platform.platform(),
        "python": platform.python_version(),
    }
    try:
        import psutil

        info["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        info["memory_used_mb"] = round(mem.used / 1024 / 1024)
        info["memory_total_mb"] = round(mem.total / 1024 / 1024)
        info["memory_percent"] = mem.percent
        disk = psutil.disk_usage("/")
        info["disk_used_gb"] = round(disk.used / 1024 / 1024 / 1024, 1)
        info["disk_total_gb"] = round(disk.total / 1024 / 1024 / 1024, 1)
        info["disk_percent"] = disk.percent
    except ImportError:
        info["psutil_missing"] = True
    return info


class AdminBasicAuthMiddleware(BaseHTTPMiddleware):
    """HTTP Basic Auth middleware for the admin UI."""

    def __init__(self, app, username: str = "admin", password: str = ""):
        super().__init__(app)
        self._username = username
        self._password = password

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/favicon.ico":
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8")
                user, pwd = decoded.split(":", 1)
                if secrets.compare_digest(user, self._username) and secrets.compare_digest(
                    pwd, self._password
                ):
                    return await call_next(request)
            except Exception:
                pass
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Nutshell Admin"'},
            content="Unauthorized",
        )


class AdminUI:
    """Encapsulates the admin dashboard state and gRPC connection."""

    def __init__(
        self,
        grpc_host: str = "localhost",
        grpc_port: int = 8086,
        mint_url: str = "http://localhost:3338",
        insecure: bool = True,
        ca_cert: str | None = None,
        client_key: str | None = None,
        client_cert: str | None = None,
    ):
        self.mint_url = mint_url.rstrip("/")
        self.grpc_host = grpc_host
        self.grpc_port = grpc_port
        self._stub: management_pb2_grpc.MintStub | None = None
        self._channel: grpc.Channel | None = None

        # Build gRPC channel
        target = f"{grpc_host}:{grpc_port}"
        if insecure:
            self._channel = grpc.insecure_channel(target)
        else:
            if not all([ca_cert, client_key, client_cert]):
                raise ValueError(
                    "mTLS requires ca_cert, client_key, and client_cert paths"
                )
            creds = grpc.ssl_channel_credentials(
                root_certificates=Path(ca_cert).read_bytes(),  # type: ignore[arg-type]
                private_key=Path(client_key).read_bytes(),  # type: ignore[arg-type]
                certificate_chain=Path(client_cert).read_bytes(),  # type: ignore[arg-type]
            )
            self._channel = grpc.secure_channel(target, creds)
        self._stub = management_pb2_grpc.MintStub(self._channel)

    @property
    def stub(self) -> management_pb2_grpc.MintStub:
        if self._stub is None:
            raise RuntimeError("gRPC stub not initialized")
        return self._stub

    def close(self):
        """Close the gRPC channel."""
        if self._channel is not None:
            self._channel.close()
            self._channel = None
            self._stub = None

    def get_info(self) -> dict:
        """Fetch mint info via gRPC."""
        try:
            resp = self.stub.GetInfo(management_pb2.GetInfoRequest())
            contacts = [
                {"method": c.method, "info": c.info} for c in resp.contact
            ]
            return {
                "name": resp.name or "",
                "version": resp.version or "",
                "description": resp.description or "",
                "long_description": resp.long_description or "",
                "motd": resp.motd or "",
                "icon_url": resp.icon_url or "",
                "urls": list(resp.urls),
                "contact": contacts,
                "pubkey": resp.pubkey or "",
                "tos_url": resp.tos_url or "",
                "connected": True,
            }
        except grpc.RpcError as e:
            return {"connected": False, "error": str(e.details())}

    async def get_mint_info_rest(self) -> dict:
        """Fetch /v1/info from the mint REST API."""
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(f"{self.mint_url}/v1/info", timeout=5)
                r.raise_for_status()
                return r.json()
        except Exception as e:
            return {"error": str(e)}

    async def get_keysets_rest(self) -> dict:
        """Fetch /v1/keysets from the mint REST API."""
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(f"{self.mint_url}/v1/keysets", timeout=5)
                r.raise_for_status()
                return r.json()
        except Exception as e:
            return {"error": str(e)}

    def update_name(self, name: str) -> str:
        self.stub.UpdateName(management_pb2.UpdateNameRequest(name=name))
        return "Name updated"

    def update_motd(self, motd: str) -> str:
        self.stub.UpdateMotd(management_pb2.UpdateMotdRequest(motd=motd))
        return "MOTD updated"

    def update_description(self, desc: str) -> str:
        self.stub.UpdateShortDescription(
            management_pb2.UpdateDescriptionRequest(description=desc)
        )
        return "Description updated"

    def update_long_description(self, desc: str) -> str:
        self.stub.UpdateLongDescription(
            management_pb2.UpdateDescriptionRequest(description=desc)
        )
        return "Long description updated"

    def update_icon_url(self, url: str) -> str:
        self.stub.UpdateIconUrl(
            management_pb2.UpdateIconUrlRequest(icon_url=url)
        )
        return "Icon URL updated"

    def update_lightning_fee(
        self, fee_percent: float | None = None, fee_min_reserve: int | None = None
    ) -> str:
        self.stub.UpdateLightningFee(
            management_pb2.UpdateLightningFeeRequest(
                fee_percent=fee_percent, fee_min_reserve=fee_min_reserve
            )
        )
        return "Lightning fee updated"

    def rotate_keyset(self, unit: str, input_fee_ppk: int | None = None) -> dict:
        resp = self.stub.RotateNextKeyset(
            management_pb2.RotateNextKeysetRequest(
                unit=unit, input_fee_ppk=input_fee_ppk
            )
        )
        return {
            "id": resp.id,
            "unit": resp.unit,
            "max_order": resp.max_order,
            "input_fee_ppk": resp.input_fee_ppk,
        }

    def update_quote_ttl(
        self, mint_ttl: int | None = None, melt_ttl: int | None = None
    ) -> str:
        self.stub.UpdateQuoteTtl(
            management_pb2.UpdateQuoteTtlRequest(
                mint_ttl=mint_ttl, melt_ttl=melt_ttl
            )
        )
        return "Quote TTL updated"

    def get_mint_quote(self, quote_id: str) -> dict:
        resp = self.stub.GetNut04Quote(
            management_pb2.GetNut04QuoteRequest(quote_id=quote_id)
        )
        q = resp.quote
        return {
            "quote": q.quote,
            "method": q.method,
            "unit": q.unit,
            "amount": q.amount,
            "state": q.state,
            "created_time": q.created_time,
            "paid_time": q.paid_time,
            "expiry": q.expiry,
        }

    def get_melt_quote(self, quote_id: str) -> dict:
        resp = self.stub.GetNut05Quote(
            management_pb2.GetNut05QuoteRequest(quote_id=quote_id)
        )
        q = resp.quote
        return {
            "quote": q.quote,
            "method": q.method,
            "unit": q.unit,
            "amount": q.amount,
            "fee_reserve": q.fee_reserve,
            "state": q.state,
            "fee_paid": q.fee_paid,
            "payment_preimage": q.payment_preimage,
            "created_time": q.created_time,
            "paid_time": q.paid_time,
            "expiry": q.expiry,
        }

    def update_mint_quote_state(self, quote_id: str, state: str) -> str:
        self.stub.UpdateNut04Quote(
            management_pb2.UpdateQuoteRequest(quote_id=quote_id, state=state)
        )
        return f"Mint quote {quote_id} → {state}"

    def update_melt_quote_state(self, quote_id: str, state: str) -> str:
        self.stub.UpdateNut05Quote(
            management_pb2.UpdateQuoteRequest(quote_id=quote_id, state=state)
        )
        return f"Melt quote {quote_id} → {state}"

    def add_url(self, url: str) -> str:
        self.stub.AddUrl(management_pb2.UpdateUrlRequest(url=url))
        return f"URL added: {url}"

    def remove_url(self, url: str) -> str:
        self.stub.RemoveUrl(management_pb2.UpdateUrlRequest(url=url))
        return f"URL removed: {url}"

    def add_contact(self, method: str, info: str) -> str:
        self.stub.AddContact(
            management_pb2.UpdateContactRequest(method=method, info=info)
        )
        return f"Contact added: {method}"

    def remove_contact(self, method: str) -> str:
        self.stub.RemoveContact(
            management_pb2.UpdateContactRequest(method=method, info="")
        )
        return f"Contact removed: {method}"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response


def create_admin_app(admin: AdminUI, admin_password: str | None = None) -> FastAPI:
    """Build the FastAPI admin dashboard application.

    Note: This UI uses HTTP Basic Auth which does not use cookies, but browsers
    cache and auto-send Basic Auth credentials for same-origin requests. This
    means CSRF attacks are theoretically possible via cross-site form submissions.
    For production deployments exposed to untrusted networks, consider placing
    the admin UI behind a VPN or reverse proxy with additional CSRF protection.
    """
    app = FastAPI(title="Nutshell Admin", docs_url=None, redoc_url=None)

    app.add_middleware(SecurityHeadersMiddleware)

    if admin_password:
        app.add_middleware(AdminBasicAuthMiddleware, password=admin_password)
    else:
        logger.warning(
            "No admin password set — admin UI is unauthenticated. "
            "Set ADMIN_PASSWORD or use --admin-password to enable authentication."
        )

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["timestamp"] = _format_timestamp

    @app.on_event("shutdown")
    async def shutdown():
        admin.close()

    @app.get("/favicon.ico")
    async def favicon():
        return Response(status_code=204)

    # --- Dashboard (home) ---
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        info = await asyncio.to_thread(admin.get_info)
        keysets = await admin.get_keysets_rest()
        sys_info = await asyncio.to_thread(_get_system_info)
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "info": info,
                "keysets": keysets,
                "sys_info": sys_info,
                "page": "dashboard",
            },
        )

    # --- Settings page ---
    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request, msg: str = ""):
        info = await asyncio.to_thread(admin.get_info)
        return templates.TemplateResponse(
            "settings.html",
            {"request": request, "info": info, "msg": msg, "page": "settings"},
        )

    @app.post("/settings/name")
    async def post_name(name: str = Form(...)):
        try:
            await asyncio.to_thread(admin.update_name, name)
            return RedirectResponse("/settings?msg=Name+updated", status_code=303)
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/motd")
    async def post_motd(motd: str = Form(...)):
        try:
            await asyncio.to_thread(admin.update_motd, motd)
            return RedirectResponse("/settings?msg=MOTD+updated", status_code=303)
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/description")
    async def post_description(description: str = Form(...)):
        try:
            await asyncio.to_thread(admin.update_description, description)
            return RedirectResponse(
                "/settings?msg=Description+updated", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/long-description")
    async def post_long_desc(long_description: str = Form(...)):
        try:
            await asyncio.to_thread(admin.update_long_description, long_description)
            return RedirectResponse(
                "/settings?msg=Long+description+updated", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/icon-url")
    async def post_icon_url(icon_url: str = Form(...)):
        try:
            await asyncio.to_thread(admin.update_icon_url, icon_url)
            return RedirectResponse(
                "/settings?msg=Icon+URL+updated", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/lightning-fee")
    async def post_lightning_fee(
        fee_percent: str = Form(""), fee_min_reserve: str = Form("")
    ):
        try:
            fp = float(fee_percent) if fee_percent else None
            fr = int(fee_min_reserve) if fee_min_reserve else None
        except (ValueError, TypeError):
            return RedirectResponse(
                "/settings?msg=Invalid+numeric+input", status_code=303
            )
        try:
            await asyncio.to_thread(admin.update_lightning_fee, fee_percent=fp, fee_min_reserve=fr)
            return RedirectResponse(
                "/settings?msg=Lightning+fee+updated", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/quote-ttl")
    async def post_quote_ttl(
        mint_ttl: str = Form(""), melt_ttl: str = Form("")
    ):
        try:
            mt = int(mint_ttl) if mint_ttl else None
            me = int(melt_ttl) if melt_ttl else None
        except (ValueError, TypeError):
            return RedirectResponse(
                "/settings?msg=Invalid+numeric+input", status_code=303
            )
        try:
            await asyncio.to_thread(admin.update_quote_ttl, mint_ttl=mt, melt_ttl=me)
            return RedirectResponse(
                "/settings?msg=Quote+TTL+updated", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/url/add")
    async def post_add_url(url: str = Form(...)):
        try:
            await asyncio.to_thread(admin.add_url, url)
            return RedirectResponse("/settings?msg=URL+added", status_code=303)
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/url/remove")
    async def post_remove_url(url: str = Form(...)):
        try:
            await asyncio.to_thread(admin.remove_url, url)
            return RedirectResponse("/settings?msg=URL+removed", status_code=303)
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/contact/add")
    async def post_add_contact(method: str = Form(...), info: str = Form(...)):
        try:
            await asyncio.to_thread(admin.add_contact, method, info)
            return RedirectResponse(
                "/settings?msg=Contact+added", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    @app.post("/settings/contact/remove")
    async def post_remove_contact(method: str = Form(...)):
        try:
            await asyncio.to_thread(admin.remove_contact, method)
            return RedirectResponse(
                "/settings?msg=Contact+removed", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/settings?msg=Operation+failed", status_code=303
            )

    # --- Keysets page ---
    @app.get("/keysets", response_class=HTMLResponse)
    async def keysets_page(request: Request, msg: str = ""):
        keysets = await admin.get_keysets_rest()
        return templates.TemplateResponse(
            "keysets.html",
            {"request": request, "keysets": keysets, "msg": msg, "page": "keysets"},
        )

    @app.post("/keysets/rotate")
    async def post_rotate(unit: str = Form("sat"), input_fee_ppk: str = Form("")):
        try:
            fee = int(input_fee_ppk) if input_fee_ppk else None
        except (ValueError, TypeError):
            return RedirectResponse(
                "/keysets?msg=Invalid+numeric+input", status_code=303
            )
        try:
            result = await asyncio.to_thread(admin.rotate_keyset, unit, input_fee_ppk=fee)
            return RedirectResponse(
                f"/keysets?msg=Rotated:+{result['id']}", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/keysets?msg=Operation+failed", status_code=303
            )

    # --- Quotes page ---
    @app.get("/quotes", response_class=HTMLResponse)
    async def quotes_page(request: Request, msg: str = ""):
        return templates.TemplateResponse(
            "quotes.html",
            {"request": request, "msg": msg, "page": "quotes"},
        )

    @app.post("/quotes/lookup")
    async def post_lookup_quote(
        request: Request,
        quote_type: str = Form("mint"),
        quote_id: str = Form(...),
    ):
        if quote_type not in {"mint", "melt"}:
            return RedirectResponse(
                "/quotes?msg=Invalid+quote+type", status_code=303
            )
        try:
            if quote_type == "mint":
                q = await asyncio.to_thread(admin.get_mint_quote, quote_id)
            else:
                q = await asyncio.to_thread(admin.get_melt_quote, quote_id)
            return templates.TemplateResponse(
                "quotes.html",
                {
                    "request": request,
                    "msg": "",
                    "quote": q,
                    "quote_type": quote_type,
                    "page": "quotes",
                },
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/quotes?msg=Operation+failed", status_code=303
            )

    @app.post("/quotes/update-state")
    async def post_update_quote_state(
        quote_type: str = Form(...),
        quote_id: str = Form(...),
        state: str = Form(...),
    ):
        if quote_type not in {"mint", "melt"}:
            return RedirectResponse(
                "/quotes?msg=Invalid+quote+type", status_code=303
            )
        # Validate quote state
        if quote_type == "mint":
            allowed = VALID_MINT_QUOTE_STATES
        else:
            allowed = VALID_MELT_QUOTE_STATES
        if state not in allowed:
            return RedirectResponse(
                "/quotes?msg=Invalid+quote+state", status_code=303
            )
        try:
            if quote_type == "mint":
                await asyncio.to_thread(admin.update_mint_quote_state, quote_id, state)
            else:
                await asyncio.to_thread(admin.update_melt_quote_state, quote_id, state)
            return RedirectResponse(
                f"/quotes?msg=Quote+{quote_id}+updated+to+{state}", status_code=303
            )
        except grpc.RpcError as e:
            logger.error("gRPC error: %s", e.details())
            return RedirectResponse(
                "/quotes?msg=Operation+failed", status_code=303
            )

    # --- Monitoring page ---
    @app.get("/monitoring", response_class=HTMLResponse)
    async def monitoring_page(request: Request):
        sys_info = await asyncio.to_thread(_get_system_info)
        mint_info = await admin.get_mint_info_rest()
        return templates.TemplateResponse(
            "monitoring.html",
            {
                "request": request,
                "sys_info": sys_info,
                "mint_info": mint_info,
                "page": "monitoring",
            },
        )

    # --- JSON API for live polling ---
    @app.get("/api/system")
    async def api_system():
        return await asyncio.to_thread(_get_system_info)

    @app.get("/api/info")
    async def api_info():
        return await asyncio.to_thread(admin.get_info)

    return app
