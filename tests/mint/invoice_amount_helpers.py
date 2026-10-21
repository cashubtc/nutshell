from uuid import uuid4

from cashu.core.base import BlindedMessage, BlindedSignature, MintQuote, Proof, Unit
from cashu.core.crypto.b_dhke import step1_alice, step3_alice
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.models import PostMintBatchRequest
from cashu.core.split import amount_split
from cashu.mint.ledger import Ledger


def make_outputs(
    ledger: Ledger, amount: int, unit: Unit
) -> tuple[list[BlindedMessage], list[tuple[str, PrivateKey]]]:
    keyset = next(k for k in ledger.keysets.values() if k.active and k.unit == unit)
    outputs = []
    secrets = []
    for denomination in amount_split(amount):
        secret = uuid4().hex
        blinded, blinding = step1_alice(secret)
        outputs.append(
            BlindedMessage(amount=denomination, id=keyset.id, B_=blinded.format().hex())
        )
        secrets.append((secret, blinding))
    return outputs, secrets


def unblind_promises(
    ledger: Ledger,
    promises: list[BlindedSignature],
    secrets: list[tuple[str, PrivateKey]],
) -> list[Proof]:
    assert len(promises) == len(secrets)
    proofs = []
    for promise, (secret, blinding) in zip(promises, secrets):
        public_keys = ledger.keysets[promise.id].public_keys
        assert public_keys is not None
        signature = step3_alice(
            PublicKey(bytes.fromhex(promise.C_)),
            blinding,
            public_keys[promise.amount],
        )
        proofs.append(
            Proof(
                id=promise.id,
                amount=promise.amount,
                secret=secret,
                C=signature.format().hex(),
            )
        )
    return proofs


async def issue(
    ledger: Ledger, quotes: list[MintQuote], outputs: list[BlindedMessage], batch: bool
) -> list[BlindedSignature]:
    if batch:
        return await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[q.quote for q in quotes],
                quote_amounts=[q.amount for q in quotes],
                outputs=outputs,
            )
        )
    assert len(quotes) == 1
    return await ledger.mint(quote_id=quotes[0].quote, outputs=outputs)
