import shutil
import time
from pathlib import Path
from typing import Dict, List

import pytest
import pytest_asyncio

from cashu.core.base import Proof
from cashu.core.helpers import async_unwrap, sum_proofs
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT, mint


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        assert exc.args[0] == msg, Exception(
            f"Expected error: {msg}, got: {exc.args[0]}"
        )


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


async def reset_wallet_db(wallet: Wallet):
    await wallet.db.execute("DELETE FROM proofs")
    await wallet.db.execute("DELETE FROM proofs_used")
    await wallet.db.execute("UPDATE secret_derivation SET counter = 0")


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = Wallet1(
        url=SERVER_ENDPOINT,
        db="data/wallet1",
        name="wallet1",
        private_key="TEST_WALLET_PRIVATE_KEY_1",
    )
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    wallet1.status()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2(mint):
    wallet2 = Wallet2(
        url=SERVER_ENDPOINT,
        db="data/wallet2",
        name="wallet2",
        private_key="TEST_WALLET_PRIVATE_KEY_2",
    )
    await migrate_databases(wallet2.db, migrations)
    await wallet2.load_mint()
    wallet2.status()
    yield wallet2


@pytest_asyncio.fixture(scope="function")
async def wallet3(mint):
    dirpath = Path("data/wallet3")
    if dirpath.exists() and dirpath.is_dir():
        shutil.rmtree(dirpath)

    wallet3 = Wallet1(
        url=SERVER_ENDPOINT,
        db="data/wallet3",
        name="wallet3",
        private_key="TEST_PRIVATE_KEY",
    )
    await migrate_databases(wallet3.db, migrations)
    await wallet3.db.execute("DELETE FROM proofs")
    await wallet3.db.execute("DELETE FROM proofs_used")
    await wallet3.load_mint()
    wallet3.status()
    yield wallet3


@pytest.mark.asyncio
async def test_get_keys(wallet1: Wallet):
    assert wallet1.keys.public_keys
    assert len(wallet1.keys.public_keys) == settings.max_order
    keyset = await wallet1._get_keys(wallet1.url)
    assert keyset.id is not None
    assert type(keyset.id) == str
    assert len(keyset.id) > 0


@pytest.mark.asyncio
async def test_get_keyset(wallet1: Wallet):
    assert wallet1.keys.public_keys
    assert len(wallet1.keys.public_keys) == settings.max_order
    # let's get the keys first so we can get a keyset ID that we use later
    keys1 = await wallet1._get_keys(wallet1.url)
    # gets the keys of a specific keyset
    assert keys1.id is not None
    assert keys1.public_keys is not None
    keys2 = await wallet1._get_keys_of_keyset(wallet1.url, keys1.id)
    assert keys2.public_keys is not None
    assert len(keys1.public_keys) == len(keys2.public_keys)


@pytest.mark.asyncio
async def test_get_info(wallet1: Wallet):
    info = await wallet1._get_info(wallet1.url)
    assert info.name


@pytest.mark.asyncio
async def test_get_nonexistent_keyset(wallet1: Wallet):
    await assert_err(
        wallet1._get_keys_of_keyset(wallet1.url, "nonexistent"),
        "Mint Error: keyset does not exist",
    )


@pytest.mark.asyncio
async def test_get_keyset_ids(wallet1: Wallet):
    keyset = await wallet1._get_keyset_ids(wallet1.url)
    assert type(keyset) == list
    assert len(keyset) > 0
    assert keyset[-1] == wallet1.keyset_id


@pytest.mark.asyncio
async def test_mint(wallet1: Wallet):
    await wallet1.mint(64)
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_mint_amounts(wallet1: Wallet):
    """Mint predefined amounts"""
    amts = [1, 1, 1, 2, 2, 4, 16]
    await wallet1.mint(amount=sum(amts), split=amts)
    assert wallet1.balance == 27
    assert wallet1.proof_amounts == amts


@pytest.mark.asyncio
async def test_mint_amounts_wrong_sum(wallet1: Wallet):
    """Mint predefined amounts"""
    amts = [1, 1, 1, 2, 2, 4, 16]
    await assert_err(
        wallet1.mint(amount=sum(amts) + 1, split=amts),
        "split must sum to amount",
    )


@pytest.mark.asyncio
async def test_mint_amounts_wrong_order(wallet1: Wallet):
    """Mint amount that is not part in 2^n"""
    amts = [1, 2, 3]
    await assert_err(
        wallet1.mint(amount=sum(amts), split=[1, 2, 3]),
        f"Can only mint amounts with 2^n up to {2**settings.max_order}.",
    )


@pytest.mark.asyncio
async def test_split(wallet1: Wallet):
    await wallet1.mint(64)
    p1, p2 = await wallet1.split(wallet1.proofs, 20)
    assert wallet1.balance == 64
    assert sum_proofs(p1) == 44
    assert [p.amount for p in p1] == [4, 8, 32]
    assert sum_proofs(p2) == 20
    assert [p.amount for p in p2] == [4, 16]
    assert all([p.id == wallet1.keyset_id for p in p1])
    assert all([p.id == wallet1.keyset_id for p in p2])


@pytest.mark.asyncio
async def test_split_to_send(wallet1: Wallet):
    await wallet1.mint(64)
    keep_proofs, spendable_proofs = await wallet1.split_to_send(
        wallet1.proofs, 32, set_reserved=True
    )
    get_spendable = await wallet1._select_proofs_to_send(wallet1.proofs, 32)
    assert keep_proofs == get_spendable

    assert sum_proofs(spendable_proofs) == 32
    assert wallet1.balance == 64
    assert wallet1.available_balance == 32


@pytest.mark.asyncio
async def test_split_more_than_balance(wallet1: Wallet):
    await wallet1.mint(64)
    await assert_err(
        wallet1.split(wallet1.proofs, 128),
        "Mint Error: split amount is higher than the total sum.",
    )
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_split_to_send_more_than_balance(wallet1: Wallet):
    await wallet1.mint(64)
    await assert_err(
        wallet1.split_to_send(wallet1.proofs, 128, set_reserved=True),
        "balance too low.",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_double_spend(wallet1: Wallet):
    doublespend = await wallet1.mint(64)
    await wallet1.split(wallet1.proofs, 20)
    await assert_err(
        wallet1.split(doublespend, 20),
        f"Mint Error: tokens already spent. Secret: {doublespend[0]['secret']}",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_duplicate_proofs_double_spent(wallet1: Wallet):
    doublespend = await wallet1.mint(64)
    await assert_err(
        wallet1.split(wallet1.proofs + doublespend, 20),
        "Mint Error: proofs already pending.",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_send_and_redeem(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    _, spendable_proofs = await wallet1.split_to_send(  # type: ignore
        wallet1.proofs, 32, set_reserved=True
    )
    await wallet2.redeem(spendable_proofs)
    assert wallet2.balance == 32

    assert wallet1.balance == 64
    assert wallet1.available_balance == 32
    await wallet1.invalidate(spendable_proofs)
    assert wallet1.balance == 32
    assert wallet1.available_balance == 32


@pytest.mark.asyncio
async def test_invalidate_unspent_proofs(wallet1: Wallet):
    """Try to invalidate proofs that have not been spent yet. Should not work!"""
    await wallet1.mint(64)
    await wallet1.invalidate(wallet1.proofs)
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_invalidate_unspent_proofs_without_checking(wallet1: Wallet):
    """Try to invalidate proofs that have not been spent yet but force no check."""
    await wallet1.mint(64)
    await wallet1.invalidate(wallet1.proofs, check_spendable=False)
    assert wallet1.balance == 0


@pytest.mark.asyncio
async def test_split_invalid_amount(wallet1: Wallet):
    await wallet1.mint(64)
    await assert_err(
        wallet1.split(wallet1.proofs, -1),
        "Mint Error: invalid split amount: -1",
    )


@pytest.mark.asyncio
async def test_split_with_secret(wallet1: Wallet):
    await wallet1.mint(64)
    secret = f"asdasd_{time.time()}"
    w1_frst_proofs, w1_scnd_proofs = await wallet1.split(
        wallet1.proofs, 32, scnd_secret=secret
    )
    # check if index prefix is in secret
    assert w1_scnd_proofs[0].secret == "0:" + secret


@pytest.mark.asyncio
async def test_redeem_without_secret(wallet1: Wallet):
    await wallet1.mint(64)
    # strip away the secrets
    w1_scnd_proofs_manipulated = wallet1.proofs.copy()
    for p in w1_scnd_proofs_manipulated:
        p.secret = ""
    await assert_err(
        wallet1.redeem(w1_scnd_proofs_manipulated),
        "Mint Error: no secret in proof.",
    )


@pytest.mark.asyncio
async def no_test_p2sh(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    # p2sh test
    p2shscript = await wallet1.create_p2sh_lock()
    txin_p2sh_address = p2shscript.address
    lock = f"P2SH:{txin_p2sh_address}"
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, lock)

    assert send_proofs[0].secret.startswith("P2SH:")

    frst_proofs, scnd_proofs = await wallet2.redeem(
        send_proofs, scnd_script=p2shscript.script, scnd_siganture=p2shscript.signature
    )
    assert len(frst_proofs) == 0
    assert len(scnd_proofs) == 1
    assert sum_proofs(scnd_proofs) == 8
    assert wallet2.balance == 8


@pytest.mark.asyncio
async def test_p2sh_receive_wrong_script(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    # p2sh test
    p2shscript = await wallet1.create_p2sh_lock()
    txin_p2sh_address = p2shscript.address
    lock = f"P2SH:{txin_p2sh_address}"
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, lock)  # type: ignore

    wrong_script = "asad" + p2shscript.script

    await assert_err(
        wallet2.redeem(
            send_proofs, scnd_script=wrong_script, scnd_siganture=p2shscript.signature
        ),
        "Mint Error: ('Script verification failed:', VerifyScriptError('scriptPubKey returned false'))",
    )
    assert wallet2.balance == 0


@pytest.mark.asyncio
async def test_p2sh_receive_wrong_signature(wallet1: Wallet, wallet2: Wallet):
    await wallet1.mint(64)
    # p2sh test
    p2shscript = await wallet1.create_p2sh_lock()
    txin_p2sh_address = p2shscript.address
    lock = f"P2SH:{txin_p2sh_address}"
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, lock)  # type: ignore

    wrong_signature = "asda" + p2shscript.signature

    await assert_err(
        wallet2.redeem(
            send_proofs, scnd_script=p2shscript.script, scnd_siganture=wrong_signature
        ),
        "Mint Error: ('Script evaluation failed:', EvalScriptError('EvalScript: OP_RETURN called'))",
    )
    assert wallet2.balance == 0


@pytest.mark.asyncio
async def test_bump_secret_derivation(wallet3: Wallet):
    wallet3.private_key = "TEST_PRIVATE_KEY"
    wallet3._init_bip32()
    secrets1, rs1 = await wallet3.generate_n_secrets(5)
    secrets2, rs2 = await wallet3.generate_secrets_from_to(0, 4)
    assert secrets1 == secrets2
    assert [r.private_key for r in rs1] == [r.private_key for r in rs2]
    assert secrets1 == [
        "1576adb6d9848408bbffdcccca60b045accfd70c0caebc29b42934bb44b19a20",
        "1d42c69cb4404e7ab76e7ad1b4b415e46ed4c7fa9d8510c46e23366bfa19827f",
        "b78a9d30671e1768e7d79a3284de234bbe49db905482134eb614c1e4564438ac",
        "703a224a42ef0ae5ceed6ec6b92131fea840e51c5b1938673746098a6bf81163",
        "7005b8ddbc61d5c018e1979f919aeafeabebc5b8eb61752efb2076873033b918",
    ]


@pytest.mark.asyncio
async def test_bump_secret_derivation_two_steps(wallet3: Wallet):
    wallet3.private_key = "TEST_PRIVATE_KEY"
    wallet3._init_bip32()
    secrets1_1, rs1_1 = await wallet3.generate_n_secrets(2)
    secrets1_2, rs1_2 = await wallet3.generate_n_secrets(3)
    secrets1 = secrets1_1 + secrets1_2
    rs1 = rs1_1 + rs1_2
    secrets2, rs2 = await wallet3.generate_secrets_from_to(0, 4)
    assert secrets1 == secrets2
    assert [r.private_key for r in rs1] == [r.private_key for r in rs2]
    assert secrets1 == [
        "1576adb6d9848408bbffdcccca60b045accfd70c0caebc29b42934bb44b19a20",
        "1d42c69cb4404e7ab76e7ad1b4b415e46ed4c7fa9d8510c46e23366bfa19827f",
        "b78a9d30671e1768e7d79a3284de234bbe49db905482134eb614c1e4564438ac",
        "703a224a42ef0ae5ceed6ec6b92131fea840e51c5b1938673746098a6bf81163",
        "7005b8ddbc61d5c018e1979f919aeafeabebc5b8eb61752efb2076873033b918",
    ]


@pytest.mark.asyncio
async def test_generate_secrets_from_to(wallet3: Wallet):
    wallet3.private_key = "TEST_PRIVATE_KEY"
    wallet3._init_bip32()
    secrets1, rs1 = await wallet3.generate_secrets_from_to(0, 4)
    assert len(secrets1) == 5
    secrets2, rs2 = await wallet3.generate_secrets_from_to(2, 4)
    assert len(secrets2) == 3
    assert secrets1[2:] == secrets2
    assert [r.private_key for r in rs1[2:]] == [r.private_key for r in rs2]
    assert secrets1 == [
        "1576adb6d9848408bbffdcccca60b045accfd70c0caebc29b42934bb44b19a20",
        "1d42c69cb4404e7ab76e7ad1b4b415e46ed4c7fa9d8510c46e23366bfa19827f",
        "b78a9d30671e1768e7d79a3284de234bbe49db905482134eb614c1e4564438ac",
        "703a224a42ef0ae5ceed6ec6b92131fea840e51c5b1938673746098a6bf81163",
        "7005b8ddbc61d5c018e1979f919aeafeabebc5b8eb61752efb2076873033b918",
    ]


@pytest.mark.asyncio
async def test_restore_wallet_after_mint(wallet3: Wallet):
    await reset_wallet_db(wallet3)
    await wallet3.mint(64)
    assert wallet3.balance == 64
    await reset_wallet_db(wallet3)
    await wallet3.load_proofs()
    wallet3.proofs = []
    assert wallet3.balance == 0
    await wallet3.restore_promises(0, 20)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_split_to_send(wallet3: Wallet):
    wallet3.private_key += "1"
    wallet3._init_bip32()
    await reset_wallet_db(wallet3)

    await wallet3.mint(64)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(  # type: ignore
        wallet3.proofs, 32, set_reserved=True
    )

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs()
    wallet3.proofs = []
    assert wallet3.balance == 0
    await wallet3.restore_promises(0, 100)
    assert wallet3.balance == 64 * 2
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_send_and_receive(wallet3: Wallet, wallet2: Wallet):
    wallet3.private_key += "2"
    wallet3._init_bip32()
    await reset_wallet_db(wallet3)

    await wallet3.mint(64)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(  # type: ignore
        wallet3.proofs, 32, set_reserved=True
    )

    await wallet2.redeem(spendable_proofs)

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises(0, 100)
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
    wallet3.private_key += "3"
    wallet3._init_bip32()
    await reset_wallet_db(wallet3)

    await wallet3.mint(64)
    assert wallet3.balance == 64

    _, spendable_proofs = await wallet3.split_to_send(  # type: ignore
        wallet3.proofs, 32, set_reserved=True
    )

    await wallet3.redeem(spendable_proofs)

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises(0, 100)
    assert wallet3.balance == 64 + 2 * 32 + 32
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 64


@pytest.mark.asyncio
async def test_restore_wallet_after_send_twice(
    wallet3: Wallet,
):
    box = ProofBox()
    wallet3.private_key += "4.0"
    wallet3._init_bip32()
    await reset_wallet_db(wallet3)

    await wallet3.mint(2)
    box.add(wallet3.proofs)
    assert wallet3.balance == 2

    keep_proofs, spendable_proofs = await wallet3.split_to_send(  # type: ignore
        wallet3.proofs, 1, set_reserved=True
    )
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
    await wallet3.restore_promises(0, 10)
    box.add(wallet3.proofs)
    assert wallet3.balance == 5
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 2

    # again

    _, spendable_proofs = await wallet3.split_to_send(  # type: ignore
        wallet3.proofs, 1, set_reserved=True
    )
    box.add(wallet3.proofs)

    assert wallet3.available_balance == 1
    await wallet3.redeem(spendable_proofs)
    box.add(wallet3.proofs)
    assert wallet3.available_balance == 2

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises(0, 15)
    box.add(wallet3.proofs)
    assert wallet3.balance == 7
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 2


@pytest.mark.asyncio
async def test_restore_wallet_after_send_and_self_receive_nonquadratic_value(
    wallet3: Wallet,
):
    box = ProofBox()
    wallet3.private_key += "4"
    wallet3._init_bip32()
    await reset_wallet_db(wallet3)

    await wallet3.mint(64)
    box.add(wallet3.proofs)
    assert wallet3.balance == 64

    keep_proofs, spendable_proofs = await wallet3.split_to_send(  # type: ignore
        wallet3.proofs, 10, set_reserved=True
    )
    box.add(wallet3.proofs)

    assert wallet3.available_balance == 64 - 10
    await wallet3.redeem(spendable_proofs)
    box.add(wallet3.proofs)
    assert wallet3.available_balance == 64

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises(0, 20)
    box.add(wallet3.proofs)
    assert wallet3.balance == 138
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 64

    # again

    _, spendable_proofs = await wallet3.split_to_send(  # type: ignore
        wallet3.proofs, 12, set_reserved=True
    )

    assert wallet3.available_balance == 64 - 12
    await wallet3.redeem(spendable_proofs)
    assert wallet3.available_balance == 64

    await reset_wallet_db(wallet3)
    await wallet3.load_proofs(reload=True)
    assert wallet3.proofs == []
    assert wallet3.balance == 0
    await wallet3.restore_promises(0, 50)
    assert wallet3.balance == 182
    await wallet3.invalidate(wallet3.proofs)
    assert wallet3.balance == 64
