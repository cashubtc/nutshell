from typing import List, Union

from cashu.core.errors import CashuError
from cashu.wallet.utils import sanitize_url


async def assert_err(f, msg: Union[str, CashuError]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        error_message: str = str(exc.args[0])
        if isinstance(msg, CashuError):
            if msg.detail not in error_message:
                raise Exception(
                    f"CashuError. Expected error: {msg.detail}, got: {error_message}"
                )
            return
        if msg not in error_message:
            raise Exception(f"Expected error: {msg}, got: {error_message}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


async def assert_err_multiple(f, msgs: List[str]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        for msg in msgs:
            if msg in str(exc.args[0]):
                return
        raise Exception(f"Expected error: {msgs}, got: {exc.args[0]}")
    raise Exception(f"Expected error: {msgs}, got no error")


def test_sanitize_url():
    url = "https://localhost:3338"
    assert sanitize_url(url) == "https://localhost:3338"

    url = "https://mint.com:3338"
    assert sanitize_url(url) == "https://mint.com:3338"

    url = "https://Mint.com:3338"
    assert sanitize_url(url) == "https://mint.com:3338"

    url = "https://mint.com:3338/"
    assert sanitize_url(url) == "https://mint.com:3338"

    url = "https://mint.com:3338/abc"
    assert sanitize_url(url) == "https://mint.com:3338/abc"

    url = "https://mint.com:3338/Abc"
    assert sanitize_url(url) == "https://mint.com:3338/Abc"

    url = "https://mint.com:3338/abc/"
    assert sanitize_url(url) == "https://mint.com:3338/abc"

    url = "https://mint.com:3338/Abc/"
    assert sanitize_url(url) == "https://mint.com:3338/Abc"

    url = "https://Mint.com:3338/Abc/def"
    assert sanitize_url(url) == "https://mint.com:3338/Abc/def"
