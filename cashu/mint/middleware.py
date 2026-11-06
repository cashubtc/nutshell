import gzip
import zlib
from contextlib import AsyncExitStack

import brotli
import zstandard as zstd
from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import (
    request_validation_exception_handler as _request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.datastructures import Headers
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..core.base import AuthProof
from ..core.crypto.keys import is_bls_keyset
from ..core.nuts.nut22 import relative_request_target
from ..core.settings import settings
from .limit import _rate_limit_exceeded_handler, limiter_global

if settings.debug_profiling:
    from fastapi_profiler import PyInstrumentProfilerMiddleware

from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from .startup import auth_ledger


def add_middlewares(app: FastAPI):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
    app.add_middleware(CompressionMiddleware)

    if settings.debug_profiling:
        assert PyInstrumentProfilerMiddleware is not None
        app.add_middleware(PyInstrumentProfilerMiddleware)

    if settings.mint_rate_limit:
        app.state.limiter = limiter_global
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.add_middleware(SlowAPIMiddleware)

    if settings.mint_require_auth:
        app.add_middleware(BlindAuthMiddleware)
        app.add_middleware(ClearAuthMiddleware)
        app.add_middleware(WebSocketAuthMiddleware)


class ClearAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if (
            settings.mint_require_auth
            and auth_ledger.mint_info.requires_clear_auth_path(
                method=request.method, path=protected_request_path(request.scope)
            )
        ):
            clear_auth_token = request.headers.get("clear-auth")
            if not clear_auth_token:
                raise Exception("Missing clear auth token.")
            try:
                user = await auth_ledger.verify_clear_auth(
                    clear_auth_token=clear_auth_token
                )
                request.state.user = user
            except Exception as e:
                raise e
        return await call_next(request)


def request_target(scope) -> str:
    """The NUT-10 request target: the path relative to the mint URL, plus the query, as sent.

    The ASGI root_path is the mint's own mount prefix; a proxy that strips its prefix leaves none.
    """
    raw_path = scope.get("raw_path")
    # Some ASGI transports include the query in raw_path.
    path = (
        raw_path.split(b"?", 1)[0]
        if raw_path is not None
        else scope["path"].encode("utf-8")
    )
    target = relative_request_target(path, scope.get("root_path", ""))
    if scope["query_string"]:
        target += "?" + scope["query_string"].decode("ascii")
    return target


def protected_request_path(scope: Scope) -> str:
    """Match protected endpoints against the path used by ASGI routing."""
    path = scope["path"]
    root = scope.get("root_path", "").rstrip("/")
    return (
        (path[len(root) :] or "/")
        if root and (path == root or path.startswith(root + "/"))
        else path
    )


class WebSocketAuthMiddleware:
    """Authorize a WebSocket's HTTP upgrade before accepting the connection."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "websocket" or not settings.mint_require_auth:
            await self.app(scope, receive, send)
            return
        target = request_target(scope)
        path = protected_request_path(scope)
        headers = Headers(scope=scope)
        async with AsyncExitStack() as authorization:
            try:
                if auth_ledger.mint_info.requires_clear_auth_path("GET", path):
                    token = headers.get("clear-auth")
                    if token is None:
                        raise ValueError("Missing clear auth token")
                    user = await auth_ledger.verify_clear_auth(clear_auth_token=token)
                    scope.setdefault("state", {})["user"] = user
                if auth_ledger.mint_info.requires_blind_auth_path("GET", path):
                    token = headers.get("blind-auth")
                    if token is None:
                        raise ValueError("Missing blind auth token")
                    await authorization.enter_async_context(
                        auth_ledger.verify_blind_auth(
                            token,
                            method="GET",
                            target=target,
                            body=b"",
                        )
                    )
            except Exception:
                await send({"type": "websocket.close", "code": 1008})
                return

            async def authorized_send(message: Message) -> None:
                if message["type"] == "websocket.accept":
                    await authorization.aclose()
                await send(message)

            await self.app(scope, receive, authorized_send)


class BlindAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if (
            settings.mint_require_auth
            and auth_ledger.mint_info.requires_blind_auth_path(
                method=request.method, path=protected_request_path(request.scope)
            )
        ):
            blind_auth_token = request.headers.get("blind-auth")
            if not blind_auth_token:
                raise Exception("Missing blind auth token.")
            # NUT-22: a version 02 BAT signs the request it authorizes, so the
            # verifier rebuilds the request transcript from these. The body is
            # read only for version 02 tokens; Starlette caches the read for
            # the downstream app.
            target = request_target(request.scope)
            body = b""
            try:
                if is_bls_keyset(AuthProof.from_base64(blind_auth_token).id):
                    body = await request.body()
            except Exception:
                pass
            async with auth_ledger.verify_blind_auth(
                blind_auth_token,
                method=request.method,
                target=target,
                body=body,
            ):
                return await call_next(request)
        else:
            return await call_next(request)


async def request_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    This is a wrapper to the default RequestValidationException handler of FastAPI.
    This function will be called when client input is not valid.
    """
    # Rejected inputs may be arbitrarily large or contain secrets. Keep the
    # validation details without copying those values into logs and responses.
    errors = [
        {key: value for key, value in error.items() if key != "input"}
        for error in exc.errors()
    ]
    query_params = request.query_params._dict
    # Logs each error's loc, msg and type.
    detail = {
        "errors": errors,
        "query_params": query_params,
    }
    # log the error
    logger.error(detail)
    # pass on
    return await _request_validation_exception_handler(
        request, RequestValidationError(errors)
    )


class CompressionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Handle streaming responses differently
        if response.__class__.__name__ == "StreamingResponse":
            return response

        response_body = b""
        async for chunk in response.body_iterator:  # type: ignore
            response_body += chunk

        accept_encoding = request.headers.get("Accept-Encoding", "")
        content = response_body

        if "br" in accept_encoding:
            content = brotli.compress(content)
            response.headers["Content-Encoding"] = "br"
        elif "zstd" in accept_encoding:
            compressor = zstd.ZstdCompressor()
            content = compressor.compress(content)
            response.headers["Content-Encoding"] = "zstd"
        elif "gzip" in accept_encoding:
            content = gzip.compress(content)
            response.headers["Content-Encoding"] = "gzip"
        elif "deflate" in accept_encoding:
            content = zlib.compress(content)
            response.headers["Content-Encoding"] = "deflate"

        response.headers["Content-Length"] = str(len(content))
        response.headers["Vary"] = "Accept-Encoding"

        return Response(
            content=content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )
