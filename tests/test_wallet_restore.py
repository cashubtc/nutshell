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
    await wallet._load_mint()


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    wallet1.status()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2(mint):
    wallet2 = await Wallet2.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet2",
        name="wallet2",
    )
    await wallet2.load_mint()
    wallet2.status()
    yield wallet2


@pytest_asyncio.fixture(scope="function")
async def wallet3(mint):
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
    wallet3.status()
    yield wallet3


@pytest.mark.asyncio
async def test_bump_secret_derivation(wallet3: Wallet):
    await wallet3._init_private_key(
        "half depart obvious quality work element tank gorilla view sugar picture"
        " humble"
    )
    secrets1, rs1, derivation_paths1 = await wallet3.generate_n_secrets(5)
    secrets2, rs2, derivation_paths2 = await wallet3.generate_secrets_from_to(0, 4)
    assert wallet3.keyset_id == "1cCNIAZ2X/w1"
    assert secrets1 == secrets2
    assert [r.private_key for r in rs1] == [r.private_key for r in rs2]
    assert derivation_paths1 == derivation_paths2
    assert secrets1 == [
        "9bfb12704297fe90983907d122838940755fcce370ce51e9e00a4275a347c3fe",
        "dbc5e05f2b1f24ec0e2ab6e8312d5e13f57ada52594d4caf429a697d9c742490",
        "06a29fa8081b3a620b50b473fc80cde9a575c3b94358f3513c03007f8b66321e",
        "652d08c804bd2c5f2c1f3e3d8895860397df394b30473753227d766affd15e89",
        "654e5997f8a20402f7487296b6f7e463315dd52fc6f6cc5a4e35c7f6ccac77e0",
    ]
    assert derivation_paths1 == [
        "m/129372'/0'/2004500376'/0'",
        "m/129372'/0'/2004500376'/1'",
        "m/129372'/0'/2004500376'/2'",
        "m/129372'/0'/2004500376'/3'",
        "m/129372'/0'/2004500376'/4'",
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
    assert [r.private_key for r in rs1] == [r.private_key for r in rs2]


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
    assert [r.private_key for r in rs1[2:]] == [r.private_key for r in rs2]


@pytest.mark.asyncio
async def test_restore_wallet_after_mint(wallet3: Wallet):
    await reset_wallet_db(wallet3)
    invoice = await wallet3.request_mint(64)
    await wallet3.mint(64, hash=invoice.hash)
    assert wallet3.balance == 64
    await reset_wallet_db(wallet3)
    await wallet3.load_proofs()
    wallet3.proofs = []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 20)
    assert wallet3.balance == 64


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
async def test_restore_wallet_after_split_to_send(wallet3: Wallet):
    await wallet3._init_private_key(
        "half depart obvious quality work element tank gorilla view sugar picture"
        " humble"
    )
    await reset_wallet_db(wallet3)

    invoice = await wallet3.request_mint(64)
    await wallet3.mint(64, hash=invoice.hash)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 32, set_reserved=True)  # type: ignore

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs()
    wallet3.proofs = []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 100)
    assert wallet3.balance == 64 * 2
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_send_and_receive(wallet3: Wallet, wallet2: Wallet):
    await wallet3._init_private_key(
        "hello rug want adapt talent together lunar method bean expose beef position"
    )
    await reset_wallet_db(wallet3)
    invoice = await wallet3.request_mint(64)
    await wallet3.mint(64, hash=invoice.hash)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 32, set_reserved=True)  # type: ignore

    await wallet2.redeem(spendable_proofs)

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 100)
    assert wallet3.balance == 64 + 2 * 32
    await wallet3.invalidate(wallet3.proofs)
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

    invoice = await wallet3.request_mint(64)
    await wallet3.mint(64, hash=invoice.hash)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 32, set_reserved=True)  # type: ignore

    await wallet3.redeem(spendable_proofs)

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 100)
    assert wallet3.balance == 64 + 2 * 32 + 32
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_send_twice(
    wallet3: Wallet,
):
    box = ProofBox()
    wallet3.private_key = PrivateKey()
    await reset_wallet_db(wallet3)

    invoice = await wallet3.request_mint(2)
    await wallet3.mint(2, hash=invoice.hash)
    box.add(wallet3.proofs)
    assert wallet3.balance == 2

    keep_proofs, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 1, set_reserved=True)  # type: ignore
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
    await wallet3.restore_promises_from_to(0, 10)
    box.add(wallet3.proofs)
    assert wallet3.balance == 5
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 2

    # again

    _, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 1, set_reserved=True)  # type: ignore
    box.add(wallet3.proofs)

    assert wallet3.available_balance == 1
    await wallet3.redeem(spendable_proofs)
    box.add(wallet3.proofs)
    assert wallet3.available_balance == 2

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 15)
    box.add(wallet3.proofs)
    assert wallet3.balance == 7
    await wallet3.invalidate(wallet3.proofs)
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

    invoice = await wallet3.request_mint(64)
    await wallet3.mint(64, hash=invoice.hash)
    box.add(wallet3.proofs)
    assert wallet3.balance == 64

    keep_proofs, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 10, set_reserved=True)  # type: ignore
    box.add(wallet3.proofs)

    assert wallet3.available_balance == 64 - 10
    await wallet3.redeem(spendable_proofs)
    box.add(wallet3.proofs)
    assert wallet3.available_balance == 64

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 20)
    box.add(wallet3.proofs)
    assert wallet3.balance == 138
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 64

    # again

    _, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 12, set_reserved=True)  # type: ignore

    assert wallet3.available_balance == 64 - 12
    await wallet3.redeem(spendable_proofs)
    assert wallet3.available_balance == 64

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 50)
    assert wallet3.balance == 182
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 64
