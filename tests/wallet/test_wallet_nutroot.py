import pytest

from cashu.core.base import NutrootOption, TokenV4, TokenV4Proof, TokenV4Token
from cashu.core.crypto.nutroot import NUTROOT_NUMS, NutrootLeaf, serialize_nutroot_leaf
from cashu.wallet.crud import get_proofs
from cashu.wallet.wallet import Wallet
from tests.compatibility import mint_older_than
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest

pytestmark = pytest.mark.skipif(
    mint_older_than("0.22.0"), reason="Nutroot requires a v3 mint"
)


@pytest.mark.asyncio
@pytest.mark.parametrize("script_only", [False, True])
async def test_nutroot_payment_survives_storage_and_sweeps(tmp_path, script_only):
    sender = await Wallet.with_db(url=SERVER_ENDPOINT, db=str(tmp_path / "sender"))
    recipient = await Wallet.with_db(
        url=SERVER_ENDPOINT, db=str(tmp_path / "recipient")
    )
    try:
        await sender.load_mint()
        await recipient.load_mint()
        receiver = recipient.private_key.public_key.format().hex()
        requested = NutrootOption(k=receiver)
        if script_only:
            requested = NutrootOption(
                k=NUTROOT_NUMS.format().hex(),
                l=[
                    serialize_nutroot_leaf(
                        NutrootLeaf(
                            type="threshold",
                            n=1,
                            keys=[recipient.private_key.public_key],
                        )
                    ).hex()
                ],
            )
        quote = await sender.request_mint(8)
        await pay_if_regtest(quote.request)
        await sender.mint(8, quote.quote)
        _, sent = await sender.swap_to_send(sender.proofs, 8, nutroot_lock=requested)
        stored = {proof.secret: proof for proof in await get_proofs(db=sender.db)}
        assert all(
            stored[proof.secret].spend_info == proof.spend_info for proof in sent
        )
        token = TokenV4(
            m=SERVER_ENDPOINT,
            u="sat",
            t=[
                TokenV4Token(
                    i=bytes.fromhex(sent[0].id),
                    p=[TokenV4Proof.from_proof(stored[proof.secret]) for proof in sent],
                )
            ],
        )
        received = TokenV4.deserialize(token.serialize()).proofs
        recipient.validate_nutroot_proofs(received, request=requested)
        kept, _ = await recipient.redeem(received, nutroot_request=requested)
        assert sum(proof.amount for proof in kept) == 8
        assert all(proof.spend_info is None for proof in kept)
    finally:
        await sender.db.engine.dispose()
        await recipient.db.engine.dispose()


@pytest.mark.asyncio
async def test_wallet_uses_seeded_quote_keys_and_can_draw_twice(tmp_path):
    wallet = await Wallet.with_db(url=SERVER_ENDPOINT, db=str(tmp_path))
    try:
        await wallet.load_mint()
        quote = await wallet.request_mint(8)
        await pay_if_regtest(quote.request)
        assert (
            quote.privkey
            == wallet.derive_v3_quote_lock_key(0, wallet.mint_info.pubkey).to_hex()
        )
        assert (
            wallet.recover_v3_quote_key(
                quote.pubkey, wallet.mint_info.pubkey, stop=1
            ).to_hex()
            == quote.privkey
        )
        await wallet.mint(4, quote.quote)
        assert (await wallet.get_mint_quote(quote.quote)).amount_issued == 4
        await wallet.mint(4, quote.quote)
        assert (await wallet.get_mint_quote(quote.quote)).amount_issued == 8
    finally:
        await wallet.db.engine.dispose()


@pytest.mark.asyncio
async def test_multisig_payment_uses_a_signing_package_and_existing_swap(tmp_path):
    sender = await Wallet.with_db(url=SERVER_ENDPOINT, db=str(tmp_path / "sender"))
    alice = await Wallet.with_db(url=SERVER_ENDPOINT, db=str(tmp_path / "alice"))
    bob = await Wallet.with_db(url=SERVER_ENDPOINT, db=str(tmp_path / "bob"))
    try:
        for wallet in [sender, alice, bob]:
            await wallet.load_mint()
        tree = serialize_nutroot_leaf(
            NutrootLeaf(
                type="threshold",
                n=2,
                keys=[alice.private_key.public_key, bob.private_key.public_key],
            )
        )
        request = NutrootOption(k=NUTROOT_NUMS.format().hex(), l=[tree.hex()])
        quote = await sender.request_mint(8)
        await pay_if_regtest(quote.request)
        await sender.mint(8, quote.quote)
        _, sent = await sender.swap_to_send(sender.proofs, 8, nutroot_lock=request)
        secrets, factors, paths = await alice.generate_n_secrets(1)
        outputs, factors = alice._construct_outputs([8], secrets, factors)
        package = alice.prepare_nutroot_signing_package(
            sent, outputs, {proof.Y: 0 for proof in sent}
        )
        assert len(package.spends[0].signatures) == 1
        signed = package.sign([bob.private_key])
        assert len(signed.spends[0].signatures) == 2
        received = await alice.submit_nutroot_swap(
            sent, outputs, secrets, factors, paths, signed
        )
        assert sum(proof.amount for proof in received) == 8
        assert sent[0].witness is not None
    finally:
        for wallet in [sender, alice, bob]:
            await wallet.db.engine.dispose()
