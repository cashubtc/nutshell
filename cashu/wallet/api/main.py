import uvicorn

from ...core.settings import settings


def main(port=settings.api_port):
    config = uvicorn.Config("cashu.wallet.api.app:app", port=port, host="127.0.0.1")
    server = uvicorn.Server(config)
    server.run()
