from typing import Annotated, Any

from pydantic import Field, TypeAdapter, ValidationError
from pydantic_core import InitErrorDetails

from ..core.base import Proof
from ..core.settings import settings

_secret_adapter: TypeAdapter[str] = TypeAdapter(
    Annotated[str, Field(max_length=settings.mint_max_secret_length)]
)


def validate_input_secret_lengths(value: Any) -> Any:
    """Validate incoming mint secrets before request parsing constructs proofs."""
    if not isinstance(value, dict) or not isinstance(value.get("inputs"), list):
        return value

    errors: list[InitErrorDetails] = []
    for index, proof in enumerate(value["inputs"]):
        if isinstance(proof, dict) and "secret" in proof:
            secret = proof["secret"]
        elif isinstance(proof, Proof):
            secret = proof.secret
        else:
            continue

        try:
            _secret_adapter.validate_python(secret)
        except ValidationError as exc:
            for error in exc.errors(include_url=False):
                errors.append(
                    {
                        "type": error["type"],
                        "loc": ("inputs", index, "secret"),
                        "input": error["input"],
                        "ctx": error.get("ctx", {}),
                    }
                )

    if errors:
        raise ValidationError.from_exception_data("Mint request", errors)
    return value
