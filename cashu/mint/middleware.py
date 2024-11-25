import gzip
import zlib

import brotli
import zstandard as zstd
from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import (
    request_validation_exception_handler as _request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware

from ..core.settings import settings
from .limit import _rate_limit_exceeded_handler, limiter_global

if settings.debug_profiling:
    from fastapi_profiler import PyInstrumentProfilerMiddleware

from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware


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


async def request_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    This is a wrapper to the default RequestValidationException handler of FastAPI.
    This function will be called when client input is not valid.
    """
    query_params = request.query_params._dict
    detail = {
        "errors": exc.errors(),
        "query_params": query_params,
    }
    # log the error
    logger.error(detail)
    # pass on
    return await _request_validation_exception_handler(request, exc)


class CompressionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Handle streaming responses differently
        if response.__class__.__name__ == 'StreamingResponse':
            return response

        response_body = b''
        async for chunk in response.body_iterator:
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
            media_type=response.media_type
        )
