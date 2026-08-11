from fastapi import FastAPI

from cashu.core.settings import settings
from cashu.mint.app import include_mint_routers


def test_auth_enabled_does_not_mount_deprecated_transaction_routes(monkeypatch):
    monkeypatch.setattr(settings, "mint_require_auth", True)
    monkeypatch.setattr(settings, "debug_mint_only_deprecated", False)
    test_app = FastAPI()

    include_mint_routers(test_app)

    mounted_routes = {
        (method, route.path)
        for route in test_app.routes
        for method in getattr(route, "methods", set())
    }
    assert ("POST", "/v1/swap") in mounted_routes
    assert ("POST", "/mint") not in mounted_routes
    assert ("POST", "/melt") not in mounted_routes
    assert ("POST", "/split") not in mounted_routes
