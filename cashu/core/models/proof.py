from pydantic import ConfigDict, Field

from cashu.core.base import Proof
from cashu.core.settings import settings


class ProofInput(Proof):
    """Request proof whose secret is validated before hashing."""

    model_config = ConfigDict(from_attributes=True, revalidate_instances="always")

    secret: str = Field(default="", max_length=settings.mint_max_secret_length)
