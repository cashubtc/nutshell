import httpx

CONNECT_TIMEOUT = 10.0
WRITE_TIMEOUT = 10.0
POOL_TIMEOUT = 10.0
STREAM_READ_TIMEOUT = 300.0


def http_timeout(read: float) -> httpx.Timeout:
    """Bound paid invoice streams, allowing long reads between events."""
    return httpx.Timeout(
        connect=CONNECT_TIMEOUT,
        read=read,
        write=WRITE_TIMEOUT,
        pool=POOL_TIMEOUT,
    )
