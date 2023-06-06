import uvicorn

from ...core.settings import settings


def start_api_server(port=settings.api_port, host=settings.api_host):
    config = uvicorn.Config(
        "cashu.wallet.api.app:app",
        port=port,
        host=host,
    )
    server = uvicorn.Server(config)
    server.run()
