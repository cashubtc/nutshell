from typing import Annotated, Any

from pydantic import BeforeValidator

from cashu.core.base import Proof
from cashu.core.settings import settings


def validate_input_proof(value: Any) -> Any:
    """Check request secrets before constructing and hashing nested proofs."""
    secret: Any
    if isinstance(value, Proof):
        secret = value.secret
    elif isinstance(value, dict):
        secret = value.get("secret")
    else:
        return value
    if isinstance(secret, str) and len(secret) > settings.mint_max_secret_length:
        raise ValueError(f"secret too long. max: {settings.mint_max_secret_length}")
    return value


ProofInput = Annotated[Proof, BeforeValidator(validate_input_proof)]
