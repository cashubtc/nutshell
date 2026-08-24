import shutil
from pathlib import Path
from typing import Dict, List, Union

import pytest
import pytest_asyncio

from cashu.core.base import Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import CashuError
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


async def assert_err(f, msg: Union[str, CashuError]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        error_message: str = str(exc.args[0])
        if isinstance(msg, CashuError):
            if msg.detail not in error_message:
                raise Exception(
                    f"CashuError. Expected error: {msg.detail}, got: {error_message}"
                )
            return
        if msg not in error_message:
            raise Exception(f"Expected error: {msg}, got: {error_message}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


async def reset_wallet_db(wallet: Wallet):
    await wallet.db.execute("DELETE FROM proofs")
    await wallet.db.execute("DELETE FROM proofs_used")
    await wallet.db.execute("DELETE FROM keysets")
    await wallet.load_mint()


@pytest_asyncio.fixture(scope="function")
async def wallet1():
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2():
    wallet2 = await Wallet2.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet2",
        name="wallet2",
    )
    await wallet2.load_mint()
    yield wallet2


@pytest_asyncio.fixture(scope="function")
async def wallet3():
    dirpath = Path("test_data/wallet3")
    if dirpath.exists() and dirpath.is_dir():
        shutil.rmtree(dirpath)

    wallet3 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet3",
        name="wallet3",
    )
    await wallet3.db.execute("DELETE FROM proofs")
    await wallet3.db.execute("DELETE FROM proofs_used")
    await wallet3.load_mint()
    yield wallet3


@pytest.mark.asyncio
async def test_bump_secret_derivation(wallet3: Wallet):
    await wallet3._init_private_key(
        "half depart obvious quality work element tank gorilla view sugar picture"
        " humble"
    )
    secrets1, rs1, derivation_paths1 = await wallet3.generate_n_secrets(5)
    secrets2, rs2, derivation_paths2 = await wallet3.generate_secrets_from_to(0, 4)
    assert wallet3.keyset_id == "02f1b93860eb420aba7572f58465e29271bb04f2edadfd95ce2ea2d3497cc4d46a"
    assert secrets1 == secrets2
    assert [r.to_hex() for r in rs1] == [r.to_hex() for r in rs2]
    # v3 keyset: the secrets are compressed points K = k*G, not raw digests.
    assert secrets1 == [
        "03cfd343e88715c18d3b709eb36d7d3f04f7bb8bbc599f9a54ecc295221434ddee",
        "0332cd2d10c04c736192e1fc65c3ffd47b16c8a0f583895045fc72f167d1735787",
        "03b31fa0ec791a741e90732fb863bbdf661f5bd87eac67671ac359e13dfd175aca",
        "03f85008d75bede4e16881df529b718a83ff3dd51b269cccfeb8348dbf25ffb5d7",
        "02c3513bdf894f116bf8a06c916fe5fecc4ead2ec5ec4554c018bc6548af91a4f9",
    ]
    assert [r.to_hex() for r in rs1] == [
        "31c3c64bce0ea6b58f876630d0b6369899f7d781e55656a3d3a2829cd9f0f278",
        "0d050067c6fb23b5de1a2fb0fe35a28e95854118896bfc2881cfdf5459d9b9b4",
        "6a6a3e455fc04ed69dbc104ab646b117d14bf7a45a67239ca7888cfe339773ae",
        "3b2b0076a36be1f74caac27513a572484fd87c98ef76eef0113bac2cdcb7ea7a",
        "0986c294413e6c5898e85b22c051e5d60b1cb022c3f1e7b6750d7c114071ac7d",
    ]

    assert derivation_paths1 == [
        "HMAC-SHA256:02f1b93860eb420aba7572f58465e29271bb04f2edadfd95ce2ea2d3497cc4d46a:0",
        "HMAC-SHA256:02f1b93860eb420aba7572f58465e29271bb04f2edadfd95ce2ea2d3497cc4d46a:1",
        "HMAC-SHA256:02f1b93860eb420aba7572f58465e29271bb04f2edadfd95ce2ea2d3497cc4d46a:2",
        "HMAC-SHA256:02f1b93860eb420aba7572f58465e29271bb04f2edadfd95ce2ea2d3497cc4d46a:3",
        "HMAC-SHA256:02f1b93860eb420aba7572f58465e29271bb04f2edadfd95ce2ea2d3497cc4d46a:4",
    ]


@pytest.mark.asyncio
async def test_bump_secret_derivation_two_steps(wallet3: Wallet):
    await wallet3._init_private_key(
        "half depart obvious quality work element tank gorilla view sugar picture"
        " humble"
    )
    secrets1_1, rs1_1, derivation_paths1 = await wallet3.generate_n_secrets(2)
    secrets1_2, rs1_2, derivation_paths2 = await wallet3.generate_n_secrets(3)
    secrets1 = secrets1_1 + secrets1_2
    rs1 = rs1_1 + rs1_2
    secrets2, rs2, derivation_paths = await wallet3.generate_secrets_from_to(0, 4)
    assert secrets1 == secrets2
    assert [r.to_hex() for r in rs1] == [r.to_hex() for r in rs2]


@pytest.mark.asyncio
async def test_generate_secrets_from_to(wallet3: Wallet):
    await wallet3._init_private_key(
        "half depart obvious quality work element tank gorilla view sugar picture"
        " humble"
    )
    secrets1, rs1, derivation_paths1 = await wallet3.generate_secrets_from_to(0, 4)
    assert len(secrets1) == 5
    secrets2, rs2, derivation_paths2 = await wallet3.generate_secrets_from_to(2, 4)
    assert len(secrets2) == 3
    assert secrets1[2:] == secrets2
    assert [r.to_hex() for r in rs1[2:]] == [r.to_hex() for r in rs2]


@pytest.mark.asyncio
async def test_restore_wallet_after_mint(wallet3: Wallet):
    await reset_wallet_db(wallet3)
    mint_quote = await wallet3.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet3.mint(64, quote_id=mint_quote.quote)
    assert wallet3.balance == 64
    await reset_wallet_db(wallet3)
    await wallet3.load_proofs()
    wallet3.proofs = []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 20)
    assert wallet3.balance == 64

    # expect that DLEQ proofs are restored
    # NUT-12 is version-scoped: v3 proofs carry no DLEQ.
    assert all([p.dleq is None for p in wallet3.proofs])


@pytest.mark.asyncio
async def test_restore_wallet_with_invalid_mnemonic(wallet3: Wallet):
    await assert_err(
        wallet3._init_private_key(
            "half depart obvious quality work element tank gorilla view sugar picture"
            " picture"
        ),
        "Invalid mnemonic",
    )


@pytest.mark.asyncio
async def test_restore_wallet_after_swap_to_send(wallet3: Wallet):
    await wallet3._init_private_key(
        "half depart obvious quality work element tank gorilla view sugar picture"
        " humble"
    )
    await reset_wallet_db(wallet3)

    mint_quote = await wallet3.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet3.mint(64, quote_id=mint_quote.quote)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.swap_to_send(
        wallet3.proofs, 32, set_reserved=True
    )  # type: ignore

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs()
    wallet3.proofs = []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 100)
    assert wallet3.balance == 96
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_send_and_receive(wallet3: Wallet, wallet2: Wallet):
    await wallet3._init_private_key(
        "hello rug want adapt talent together lunar method bean expose beef position"
    )
    await reset_wallet_db(wallet3)
    mint_quote = await wallet3.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet3.mint(64, quote_id=mint_quote.quote)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.swap_to_send(
        wallet3.proofs, 32, set_reserved=True
    )  # type: ignore

    await wallet2.redeem(spendable_proofs)

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 100)
    assert wallet3.balance == 96
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 32


class ProofBox:
    proofs: Dict[str, Proof] = {}

    def add(self, proofs: List[Proof]) -> None:
        for proof in proofs:
            if proof.secret in self.proofs:
                if self.proofs[proof.secret].C != proof.C:
                    print("Proofs are not equal")
                    print(self.proofs[proof.secret])
                    print(proof)
            else:
                self.proofs[proof.secret] = proof


@pytest.mark.asyncio
async def test_restore_wallet_after_send_and_self_receive(wallet3: Wallet):
    await wallet3._init_private_key(
        "lucky broken tell exhibit shuffle tomato ethics virus rabbit spread measure"
        " text"
    )
    await reset_wallet_db(wallet3)

    mint_quote = await wallet3.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet3.mint(64, quote_id=mint_quote.quote)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.swap_to_send(
        wallet3.proofs, 32, set_reserved=True
    )  # type: ignore

    await wallet3.redeem(spendable_proofs)

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 100)
    assert wallet3.balance == 128
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_send_twice(
    wallet3: Wallet,
):
    box = ProofBox()
    wallet3.private_key = PrivateKey()
    await reset_wallet_db(wallet3)

    mint_quote = await wallet3.request_mint(2)
    await pay_if_regtest(mint_quote.request)
    await wallet3.mint(2, quote_id=mint_quote.quote)
    box.add(wallet3.proofs)
    assert wallet3.balance == 2

    keep_proofs, spendable_proofs = await wallet3.swap_to_send(
        wallet3.proofs, 1, set_reserved=True
    )  # type: ignore
    box.add(wallet3.proofs)
    assert wallet3.available_balance == 1
    await wallet3.redeem(spendable_proofs)
    box.add(wallet3.proofs)
    assert wallet3.available_balance == 2
    assert wallet3.balance == 2

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 10)
    box.add(wallet3.proofs)
    assert wallet3.balance == 4
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 2

    # again

    _, spendable_proofs = await wallet3.swap_to_send(
        wallet3.proofs, 1, set_reserved=True
    )  # type: ignore
    box.add(wallet3.proofs)

    assert wallet3.available_balance == 1
    await wallet3.redeem(spendable_proofs)
    box.add(wallet3.proofs)
    assert wallet3.available_balance == 2

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 15)
    box.add(wallet3.proofs)
    assert wallet3.balance == 6
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 2


@pytest.mark.asyncio
async def test_restore_wallet_after_send_and_self_receive_nonquadratic_value(
    wallet3: Wallet,
):
    box = ProofBox()
    await wallet3._init_private_key(
        "casual demise flight cradle feature hub link slim remember anger front asthma"
    )
    await reset_wallet_db(wallet3)

    mint_quote = await wallet3.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet3.mint(64, quote_id=mint_quote.quote)
    box.add(wallet3.proofs)
    assert wallet3.balance == 64

    keep_proofs, spendable_proofs = await wallet3.swap_to_send(
        wallet3.proofs, 10, set_reserved=True
    )  # type: ignore
    box.add(wallet3.proofs)

    assert wallet3.available_balance == 64 - 10
    await wallet3.redeem(spendable_proofs)
    box.add(wallet3.proofs)
    assert wallet3.available_balance == 64

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 20)
    box.add(wallet3.proofs)
    assert wallet3.balance == 84
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 64

    # again

    _, spendable_proofs = await wallet3.swap_to_send(
        wallet3.proofs, 12, set_reserved=True
    )  # type: ignore

    assert wallet3.available_balance == 64 - 12
    await wallet3.redeem(spendable_proofs)
    assert wallet3.available_balance == 64

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 50)
    assert wallet3.balance == 108
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 64

@pytest.mark.asyncio
async def test_restore_promises_derivation_paths_subset(wallet3: Wallet):
    """Restored proofs get derivation_path that matches their secret (subset restore)."""
    await reset_wallet_db(wallet3)

    # Advance counter so next mint uses indices 21+; restore then returns a subset.
    await wallet3.restore_promises_from_to(wallet3.keyset_id, 0, 20)

    mint_quote = await wallet3.request_mint(21)
    await pay_if_regtest(mint_quote.request)
    await wallet3.mint(21, quote_id=mint_quote.quote)
    assert wallet3.balance > 0

    restore_from, restore_to = 0, 40
    secrets, _, derivation_paths = await wallet3.generate_secrets_from_to(
        restore_from, restore_to
    )
    secret_to_path = dict(zip(secrets, derivation_paths))

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs()
    wallet3.proofs = []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(wallet3.keyset_id, restore_from, restore_to)

    assert len(wallet3.proofs) >= 1
    for proof in wallet3.proofs:
        expected_path = secret_to_path.get(proof.secret)
        assert expected_path is not None
        assert proof.derivation_path == expected_path, (
            f"derivation_path {proof.derivation_path!r} does not match secret "
            f"(expected {expected_path!r})"
        )
