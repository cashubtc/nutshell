"""Module-level app instance for uvicorn import."""

import os

from .app import AdminUI, create_admin_app

admin = AdminUI(
    grpc_host=os.environ.get("ADMIN_GRPC_HOST", "localhost"),
    grpc_port=int(os.environ.get("ADMIN_GRPC_PORT", "8086")),
    mint_url=os.environ.get("ADMIN_MINT_URL", "http://localhost:3338"),
    insecure=os.environ.get("ADMIN_INSECURE", "1") == "1",
    ca_cert=os.environ.get("ADMIN_CA_CERT"),
    client_key=os.environ.get("ADMIN_CLIENT_KEY"),
    client_cert=os.environ.get("ADMIN_CLIENT_CERT"),
)

app = create_admin_app(admin, admin_password=os.environ.get("ADMIN_PASSWORD"))
