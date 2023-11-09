import httpx
import pytest

from cashu.tor.tor import TorProxy


@pytest.mark.asyncio
@pytest.mark.skip(reason="Tor is not installed on CI")
async def test_tor_setup():
    tor = TorProxy(timeout=False)
    tor.run_daemon()
    socks_host, socks_port = "localhost", 9050

    proxies = {
        "all://": f"socks5://{socks_host}:{socks_port}",
    }
    client = httpx.AsyncClient(
        proxies=proxies,  # type: ignore
    )

    resp = await client.get("https://www.wikipedia.org/")
    resp.raise_for_status()
