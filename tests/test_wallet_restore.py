import shutil
from pathlib import Path
from typing import Dict, List, Union

import pytest
import pytest_asyncio

from cashu.core.base import Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import CashuError
from cashu.core.settings import settings
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
    await wallet._load_mint()


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
@pytest.mark.skipif(
    settings.debug_mint_only_deprecated,
    reason="settings.debug_mint_only_deprecated is set",
)
async def test_bump_secret_derivation(wallet3: Wallet):
    await wallet3._init_private_key(
        "half depart obvious quality work element tank gorilla view sugar picture"
        " humble"
    )
    secrets1, rs1, derivation_paths1 = await wallet3.generate_n_secrets(5)
    secrets2, rs2, derivation_paths2 = await wallet3.generate_secrets_from_to(0, 4)
    assert wallet3.keyset_id == "009a1f293253e41e"
    assert secrets1 == secrets2
    assert [r.private_key for r in rs1] == [r.private_key for r in rs2]
    assert derivation_paths1 == derivation_paths2
    for s in secrets1:
        print('"' + s + '",')
    assert secrets1 == [
        "485875df74771877439ac06339e284c3acfcd9be7abf3bc20b516faeadfe77ae",
        "8f2b39e8e594a4056eb1e6dbb4b0c38ef13b1b2c751f64f810ec04ee35b77270",
        "bc628c79accd2364fd31511216a0fab62afd4a18ff77a20deded7b858c9860c8",
        "59284fd1650ea9fa17db2b3acf59ecd0f2d52ec3261dd4152785813ff27a33bf",
        "576c23393a8b31cc8da6688d9c9a96394ec74b40fdaf1f693a6bb84284334ea0",
    ]
    for d in derivation_paths1:
        print('"' + d + '",')
    assert derivation_paths1 == [
        "m/129372'/0'/864559728'/0'",
        "m/129372'/0'/864559728'/1'",
        "m/129372'/0'/864559728'/2'",
        "m/129372'/0'/864559728'/3'",
        "m/129372'/0'/864559728'/4'",
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
    pay_if_regtest(invoice.bolt11)
    await wallet3.mint(64, id=invoice.id)
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
    pay_if_regtest(invoice.bolt11)
    await wallet3.mint(64, id=invoice.id)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 32, set_reserved=True)  # type: ignore

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs()
    wallet3.proofs = []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 100)
    assert wallet3.balance == 64 * 2
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_send_and_receive(wallet3: Wallet, wallet2: Wallet):
    await wallet3._init_private_key(
        "hello rug want adapt talent together lunar method bean expose beef position"
    )
    await reset_wallet_db(wallet3)
    invoice = await wallet3.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet3.mint(64, id=invoice.id)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 32, set_reserved=True)  # type: ignore

    await wallet2.redeem(spendable_proofs)

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 100)
    assert wallet3.balance == 64 + 2 * 32
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

    invoice = await wallet3.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet3.mint(64, id=invoice.id)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(wallet3.proofs, 32, set_reserved=True)  # type: ignore

    await wallet3.redeem(spendable_proofs)

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises_from_to(0, 100)
    assert wallet3.balance == 64 + 2 * 32 + 32
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_send_twice(
    wallet3: Wallet,
):
    box = ProofBox()
    wallet3.private_key = PrivateKey()
    await reset_wallet_db(wallet3)

    invoice = await wallet3.request_mint(2)
    pay_if_regtest(invoice.bolt11)
    await wallet3.mint(2, id=invoice.id)
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
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
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

    invoice = await wallet3.request_mint(64)
    pay_if_regtest(invoice.bolt11)
    await wallet3.mint(64, id=invoice.id)
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
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
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
    await wallet3.invalidate(wallet3.proofs, check_spendable=True)
    assert wallet3.balance == 64
