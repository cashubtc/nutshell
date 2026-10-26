import httpx

STREAM_READ_TIMEOUT = 300.0
PAYMENT_READ_TIMEOUT = 300.0


def http_timeout(read: float = 60.0) -> httpx.Timeout:
    """Bound silent backend connections, allowing longer payment/stream reads."""
    return httpx.Timeout(10.0, read=read)
