from typing import Any

from pydantic import ValidationError

from ..core.settings import settings

_MAX_SECRET_LENGTH = settings.mint_max_secret_length


def validate_input_secret_lengths(value: Any) -> Any:
    """Reject long JSON secrets before request parsing constructs proofs."""
    if not isinstance(value, dict) or not isinstance(value.get("inputs"), list):
        return value

    for index, proof in enumerate(value["inputs"]):
        if not isinstance(proof, dict):
            continue
        secret = proof.get("secret")
        if isinstance(secret, str) and len(secret) > _MAX_SECRET_LENGTH:
            raise ValidationError.from_exception_data(
                "Mint request",
                [
                    {
                        "type": "string_too_long",
                        "loc": ("inputs", index, "secret"),
                        "input": secret,
                        "ctx": {"max_length": _MAX_SECRET_LENGTH},
                    }
                ],
            )
    return value
