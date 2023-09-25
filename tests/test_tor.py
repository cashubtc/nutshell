import pytest
import requests

from cashu.tor.tor import TorProxy


# @pytest.mark.skip(reason="Tor is not installed on CI")
def test_tor_setup():
    s = requests.Session()

    tor = TorProxy(timeout=False)
    tor.run_daemon()
    assert tor.is_running()
    socks_host, socks_port = "localhost", 9050

    proxies = {
        "http": f"socks5://{socks_host}:{socks_port}",
        "https": f"socks5://{socks_host}:{socks_port}",
    }
    s.proxies.update(proxies)

    resp = s.get("https://google.com")
    resp.raise_for_status()

    tor.stop_daemon()
