from pydantic import BaseSettings, AnyUrl, Field, root_validator, SecretStr
from pathlib import Path


class MintSettings(BaseSettings):
    class Config:
        env_file = Path.home() / ".cashu" / ".env"
        env_file_encoding = "utf-8"
        allow_mutation = False

    mint_host: str = Field(description="Mint host", default="8333.space")
    mint_port: int = Field(description="Mint port", default=3338)
    mint_url: AnyUrl | None = Field(description="Mint URL", default=None)
    mint_server_host: str = Field(description="Mint server host", default="127.0.0.1")
    mint_server_port: int = Field(description="Mint server port", default=3338)

    @root_validator
    def validate_mint_url(cls, values):
        mint_url = values.get("mint_url")
        mint_host = values.get("mint_host")
        mint_port = values.get("mint_port")
        if not mint_url:
            if mint_host in ["localhost", "127.0.0.1"]:
                mint_url = f"http://{mint_host}:{mint_port}"
            else:
                mint_url = f"https://{mint_host}:{mint_port}"
        values["mint_url"] = mint_url
        return values


class CashuSettings(BaseSettings):
    class Config:
        env_file = Path.home() / ".cashu" / ".env"
        env_file_encoding = "utf-8"
        allow_mutation = False

    cashu_dir: Path = Field(description="Cashu directory", default=Path.home() / ".cashu")
    debug: bool = Field(description="Debug mode", default=False)
    tor: bool = Field(description="Use Tor", default=True)
    socks_host: str | None = Field(description="Socks host", default=None)
    socks_port: int = Field(description="Socks port", default=9050)
    lightning: bool = Field(description="Use Lightning", default=True)
    lightning_fee_percent: float = Field(description="Lightning fee percent", default=1.0, ge=0.0)
    lightning_reserve_fee_min: float = Field(description="Lightning reserve fee min", default=4000)
    mint_private_key: SecretStr | None = Field(description="Mint private key", default=None)
    lnbits_endpoint: AnyUrl | None = Field(description="Lnbits endpoint", default=None)
    lnbits_key: SecretStr | None = Field(description="Lnbits key", default=None)
    max_order: int = Field(description="Max order", default=64)

