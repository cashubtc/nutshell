import httpx

CONNECT_TIMEOUT = 10.0
WRITE_TIMEOUT = 10.0
POOL_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 60.0
STREAM_READ_TIMEOUT = 300.0
PAYMENT_READ_TIMEOUT = 300.0


def http_timeout(read: float = DEFAULT_READ_TIMEOUT) -> httpx.Timeout:
    """Bound silent backend connections, allowing longer payment/stream reads."""
    return httpx.Timeout(
        connect=CONNECT_TIMEOUT,
        read=read,
        write=WRITE_TIMEOUT,
        pool=POOL_TIMEOUT,
    )
