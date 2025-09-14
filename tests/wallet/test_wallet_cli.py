import asyncio
from typing import Tuple

import bolt11
import pytest
from click.testing import CliRunner

from cashu.core.base import TokenV4
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from cashu.wallet.wallet import Wallet
from tests.helpers import (
    get_real_invoice,
    is_deprecated_api_only,
    is_fake,
    is_regtest,
    pay_if_regtest,
)


@pytest.fixture(autouse=True, scope="session")
def cli_prefix():
    yield ["--wallet", "test_cli_wallet", "--host", settings.mint_url, "--tests"]


def get_bolt11_and_invoice_id_from_invoice_command(output: str) -> Tuple[str, str]:
    invoice = [
        line.split(" ")[1] for line in output.split("\n") if line.startswith("Invoice")
    ][0]
    invoice_id = [
        line.split(" ")[-1] for line in output.split("\n") if line.startswith("You can")
    ][0]
    return invoice, invoice_id


def get_invoice_from_invoices_command(output: str) -> dict[str, str]:
    splitted = output.split("\n")
    removed_empty_and_hiphens = [
        value for value in splitted if value and not value.startswith("-----")
    ]
    # filter only lines that have ": " in them
    removed_empty_and_hiphens = [
        value for value in removed_empty_and_hiphens if ": " in value
    ]
    dict_output = {
        f"{value.split(': ')[0]}": value.split(": ")[1]
        for value in removed_empty_and_hiphens
    }

    return dict_output


async def reset_invoices(wallet: Wallet):
    await wallet.db.execute("DELETE FROM bolt11_melt_quotes")
    await wallet.db.execute("DELETE FROM bolt11_mint_quotes")


async def init_wallet():
    settings.debug = False
    wallet = await Wallet.with_db(
        url=settings.mint_url,
        db="test_data/test_cli_wallet",
        name="test_cli_wallet",
    )
    await wallet.load_proofs()
    return wallet


def test_info(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "info"],
    )
    assert result.exception is None
    print("INFO")
    print(result.output)
    result.output.startswith(f"Version: {settings.version}")
    assert result.exit_code == 0


def test_info_with_mint(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "info", "--mint"],
    )
    assert result.exception is None
    print("INFO --MINT")
    print(result.output)
    assert "Mint name" in result.output
    assert result.exit_code == 0


def test_info_with_mnemonic(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "info", "--mnemonic"],
    )
    assert result.exception is None
    print("INFO --MNEMONIC")
    print(result.output)
    assert "Mnemonic" in result.output
    assert result.exit_code == 0


def test_balance(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "balance"],
    )
    assert result.exception is None
    print("------ BALANCE ------")
    print(result.output)
    w = asyncio.run(init_wallet())
    assert f"Balance: {w.available_balance}" in result.output
    assert result.exit_code == 0


@pytest.mark.skipif(is_fake, reason="only works with FakeWallet")
def test_pay_invoice_regtest(mint, cli_prefix):
    invoice_dict = get_real_invoice(10)
    invoice_payment_request = invoice_dict["payment_request"]
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "pay", invoice_payment_request, "-y"],
    )
    assert result.exception is None
    print("PAY INVOICE")
    print(result.output)


@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
def test_invoice(mint, cli_prefix):
    if settings.debug_mint_only_deprecated:
        pytest.skip("only works with v1 API")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000"],
    )

    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert result.exit_code == 0


@pytest.mark.skipif(is_regtest, reason="only works with FakeWallet")
def test_invoice_verbose(mint, cli_prefix):
    if settings.debug_mint_only_deprecated:
        pytest.skip("only works with v1 API")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "-v", "invoice", "1000"],
    )

    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert "Request: POST" in result.output
    assert "Response: 200" in result.output


def test_invoice_return_immediately(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "-n", "1000"],
    )

    assert result.exception is None

    invoice, invoice_id = get_bolt11_and_invoice_id_from_invoice_command(result.output)
    asyncio.run(pay_if_regtest(invoice))

    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000", "--id", invoice_id],
    )
    assert result.exception is None

    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert result.exit_code == 0


@pytest.mark.skipif(is_deprecated_api_only, reason="only works with v1 API")
def test_invoice_with_memo(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "-n", "1000", "-m", "test memo"],
    )
    assert result.exception is None

    # find word starting with ln in the output
    lines = result.output.split("\n")
    invoice_str = ""
    for line in lines:
        for word in line.split(" "):
            if word.startswith("ln"):
                invoice_str = word
                break
    if not invoice_str:
        raise Exception("No invoice found in the output")
    invoice_obj = bolt11.decode(invoice_str)
    assert invoice_obj.amount_msat == 1000_000
    assert invoice_obj.description == "test memo"


def test_invoice_with_split(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            *cli_prefix,
            "invoice",
            "10",
            "-s",
            "1",
            "-n",
        ],
    )
    assert result.exception is None

    invoice, invoice_id = get_bolt11_and_invoice_id_from_invoice_command(result.output)
    asyncio.run(pay_if_regtest(invoice))
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "10", "-s", "1", "--id", invoice_id],
    )
    assert result.exception is None

    assert result.exception is None
    wallet = asyncio.run(init_wallet())
    assert wallet.proof_amounts.count(1) >= 10


@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
def test_invoices_with_minting(cli_prefix):
    # arrange
    wallet1 = asyncio.run(init_wallet())
    asyncio.run(reset_invoices(wallet=wallet1))
    mint_quote = asyncio.run(wallet1.request_mint(64))
    asyncio.run(pay_if_regtest(mint_quote.request))
    # act
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices", "--mint"],
    )

    # assert
    print("INVOICES --mint")
    assert result.exception is None
    assert result.exit_code == 0
    assert "Received 64 sat" in result.output


def test_invoices_without_minting(cli_prefix):
    # arrange
    wallet1 = asyncio.run(init_wallet())
    asyncio.run(reset_invoices(wallet=wallet1))
    mint_quote = asyncio.run(wallet1.request_mint(64))

    # act
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices"],
    )

    # assert
    print("INVOICES")
    assert result.exception is None
    assert result.exit_code == 0
    assert "No invoices found." not in result.output
    assert "ID" in result.output
    assert "State" in result.output
    assert get_invoice_from_invoices_command(result.output)["ID"] == mint_quote.quote
    assert get_invoice_from_invoices_command(result.output)["State"] == str(
        mint_quote.state
    )


@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
def test_invoices_with_onlypaid_option(cli_prefix):
    # arrange
    wallet1 = asyncio.run(init_wallet())
    asyncio.run(reset_invoices(wallet=wallet1))
    asyncio.run(wallet1.request_mint(64))

    # act
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices", "--only-paid"],
    )

    # assert
    print("INVOICES --only-paid")
    assert result.exception is None
    assert result.exit_code == 0
    assert "No invoices found." in result.output


def test_invoices_with_onlypaid_option_without_minting(cli_prefix):
    # arrange
    wallet1 = asyncio.run(init_wallet())
    asyncio.run(reset_invoices(wallet=wallet1))
    asyncio.run(wallet1.request_mint(64))

    # act
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices", "--only-paid"],
    )

    # assert
    print("INVOICES --only-paid")
    assert result.exception is None
    assert result.exit_code == 0
    assert "No invoices found." in result.output


@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
def test_invoices_with_onlyunpaid_option(cli_prefix):
    # arrange
    wallet1 = asyncio.run(init_wallet())
    asyncio.run(reset_invoices(wallet=wallet1))
    asyncio.run(wallet1.request_mint(64))

    # act
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices", "--only-unpaid", "--mint"],
    )

    # assert
    print("INVOICES --only-unpaid --mint")
    assert result.exception is None
    assert result.exit_code == 0
    assert "No invoices found." in result.output


def test_invoices_with_onlyunpaid_option_without_minting(cli_prefix):
    # arrange
    wallet1 = asyncio.run(init_wallet())
    asyncio.run(reset_invoices(wallet=wallet1))
    mint_quote = asyncio.run(wallet1.request_mint(64))

    # act
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices", "--only-unpaid"],
    )

    # assert
    print("INVOICES --only-unpaid")
    assert result.exception is None
    assert result.exit_code == 0
    assert "No invoices found." not in result.output
    assert "ID" in result.output
    assert "State" in result.output
    assert get_invoice_from_invoices_command(result.output)["ID"] == mint_quote.quote
    assert get_invoice_from_invoices_command(result.output)["State"] == str(
        mint_quote.state
    )


def test_invoices_with_both_onlypaid_and_onlyunpaid_options(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices", "--only-paid", "--only-unpaid"],
    )
    assert result.exception is None
    print("INVOICES --only-paid --only-unpaid")
    assert result.exit_code == 0
    assert (
        "You should only choose one option: either --only-paid or --only-unpaid"
        in result.output
    )


@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
def test_invoices_with_pending_option(cli_prefix):
    # arrange
    wallet1 = asyncio.run(init_wallet())
    asyncio.run(reset_invoices(wallet=wallet1))
    asyncio.run(wallet1.request_mint(64))

    # act
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices", "--pending", "--mint"],
    )

    # assert
    print("INVOICES --pending --mint")
    assert result.exception is None
    assert result.exit_code == 0
    assert "No invoices found." in result.output


def test_invoices_with_pending_option_without_minting(cli_prefix):
    # arrange
    wallet1 = asyncio.run(init_wallet())
    asyncio.run(reset_invoices(wallet=wallet1))
    mint_quote = asyncio.run(wallet1.request_mint(64))

    # act
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoices", "--pending"],
    )

    # assert
    print("INVOICES --pending")
    assert result.exception is None
    assert result.exit_code == 0
    assert "No invoices found." not in result.output
    assert "ID" in result.output
    assert "State" in result.output
    assert get_invoice_from_invoices_command(result.output)["ID"] == mint_quote.quote
    assert get_invoice_from_invoices_command(result.output)["State"] == str(
        mint_quote.state
    )


def test_wallets(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "wallets"],
    )
    assert result.exception is None
    print("WALLETS")
    # on github this is empty
    if len(result.output):
        assert "wallet" in result.output
    assert result.exit_code == 0


def test_send(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10"],
    )
    assert result.exception is None
    print("test_send", result.output)
    token_str = result.output.split("\n")[0]
    assert "cashuB" in token_str, "output does not have a token"
    token = TokenV4.deserialize(token_str).to_tokenv3()
    assert token.token[0].proofs[0].dleq is None, "dleq included"


def test_send_with_dleq(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10", "--dleq"],
    )
    assert result.exception is None
    print("test_send_with_dleq", result.output)
    token_str = result.output.split("\n")[0]
    assert "cashuB" in token_str, "output does not have a token"
    token = TokenV4.deserialize(token_str).to_tokenv3()
    assert token.token[0].proofs[0].dleq is not None, "no dleq included"


def test_send_legacy(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10", "--legacy"],
    )
    assert result.exception is None
    print("test_send_legacy", result.output)
    # this is the legacy token in the output
    token_str = result.output.split("\n")[0]
    assert token_str.startswith("cashuAey"), "output is not as expected"


def test_send_offline(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "2", "--offline"],
    )
    assert result.exception is None
    print("SEND")
    print("test_send_without_split", result.output)
    assert "cashuB" in result.output, "output does not have a token"


def test_send_too_much(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "100000"],
    )
    assert "Balance too low" in str(result.exception)


def test_receive_tokenv3(mint, cli_prefix):
    runner = CliRunner()
    token = "cashuAeyJ0b2tlbiI6IFt7InByb29mcyI6IFt7ImlkIjogIjAwOWExZjI5MzI1M2U0MWUiLCAiYW1vdW50IjogMiwgInNlY3JldCI6ICI0NzlkY2E0MzUzNzU4MTM4N2Q1ODllMDU1MGY0Y2Q2MjFmNjE0MDM1MGY5M2Q4ZmI1OTA2YjJlMGRiNmRjYmI3IiwgIkMiOiAiMDM1MGQ0ZmI0YzdiYTMzNDRjMWRjYWU1ZDExZjNlNTIzZGVkOThmNGY4ODdkNTQwZmYyMDRmNmVlOWJjMjkyZjQ1In0sIHsiaWQiOiAiMDA5YTFmMjkzMjUzZTQxZSIsICJhbW91bnQiOiA4LCAic2VjcmV0IjogIjZjNjAzNDgwOGQyNDY5N2IyN2YxZTEyMDllNjdjNjVjNmE2MmM2Zjc3NGI4NWVjMGQ5Y2Y3MjE0M2U0NWZmMDEiLCAiQyI6ICIwMjZkNDlhYTE0MmFlNjM1NWViZTJjZGQzYjFhOTdmMjE1MDk2NTlkMDE3YWU0N2FjNDY3OGE4NWVkY2E4MGMxYmQifV0sICJtaW50IjogImh0dHA6Ly9sb2NhbGhvc3Q6MzMzNyJ9XX0="  # noqa
    result = runner.invoke(
        cli,
        [
            *cli_prefix,
            "receive",
            token,
        ],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


def test_nostr_send(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            *cli_prefix,
            "send",
            "1",
            "-n",
            "aafa164a8ab54a6b6c67bbac98a5d5aec7ea4075af8928a11478ab9d74aec4ca",
            "-y",
        ],
    )
    assert result.exception is None
    print("NOSTR_SEND")
    print(result.output)


def test_pending(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "pending"],
    )
    assert result.exception is None
    print(result.output)
    assert result.exit_code == 0


def test_selfpay(cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "selfpay"],
    )
    assert result.exception is None
    print(result.output)
    assert result.exit_code == 0


def test_send_with_lock(mint, cli_prefix):
    # call "cashu locks" first and get the lock
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "locks"],
    )
    assert result.exception is None
    print("test_send_with_lock", result.output)
    # iterate through all words and get the word that starts with "P2PK:"
    lock = None
    for word in result.output.split(" "):
        # strip the word
        word = word.strip()
        if word.startswith("P2PK:"):
            lock = word
            break
    assert lock is not None, "no lock found"
    pubkey = lock.split(":")[1]

    # now lock the token
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10", "--lock", lock],
    )
    assert result.exception is None
    print("test_send_with_lock", result.output)
    token_str = result.output.split("\n")[0]
    assert "cashuB" in token_str, "output does not have a token"
    token = TokenV4.deserialize(token_str).to_tokenv3()
    assert pubkey in token.token[0].proofs[0].secret


def test_proofs_json_structure(cli_prefix):
    """Test that proofs have correct JSON structure"""
    runner = CliRunner(mix_stderr=False)

    # First create some tokens
    result = runner.invoke(cli, [*cli_prefix, "invoice", "64"])
    assert result.exception is None

    # Verify wallet has balance
    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 64

    # Test proofs command
    result = runner.invoke(cli, [*cli_prefix, "proofs"])
    assert result.exception is None
    assert result.exit_code == 0

    # Parse JSON from stdout
    import json
    proofs = json.loads(result.stdout.strip())
    assert len(proofs) > 0, "Should have proofs to test structure"

    for proof in proofs:
        # Check field types, the required fields according to NUT-00 spec
        assert isinstance(proof["id"], str), "'id' should be string"
        assert isinstance(proof["amount"], int), "'amount' should be integer"
        assert isinstance(proof["secret"], str), "'secret' should be string"
        assert isinstance(proof["C"], str), "'C' should be string"
        assert "dleq" in proof.keys() # will not be present if '--no-dleq' is passed


def test_proofs_with_no_dleq_flag(cli_prefix):
    """Test --no-dleq flag excludes DLEQ proofs"""
    runner = CliRunner(mix_stderr=False)

    # First create some tokens
    result = runner.invoke(cli, [*cli_prefix, "invoice", "64"])
    assert result.exception is None

    # Verify wallet has balance
    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 64

    # Get proofs with DLEQ
    result_with_dleq = runner.invoke(cli, [*cli_prefix, "proofs"])
    assert result_with_dleq.exception is None

    # Get proofs without DLEQ
    result_no_dleq = runner.invoke(cli, [*cli_prefix, "proofs", "--no-dleq"])
    assert result_no_dleq.exception is None
    assert result_no_dleq.exit_code == 0

    # Parse JSON from both outputs
    import json
    proofs_with_dleq = json.loads(result_with_dleq.stdout.strip())
    proofs_no_dleq = json.loads(result_no_dleq.stdout.strip())

    # Should have same number of proofs
    assert len(proofs_with_dleq) == len(proofs_no_dleq)
    assert len(proofs_with_dleq) > 0, "Should have proofs to test"

    # No DLEQ version should not have dleq field
    for proof in proofs_no_dleq:
        # Check field types, the required fields according to NUT-00 spec
        assert isinstance(proof["id"], str), "'id' should be string"
        assert isinstance(proof["amount"], int), "'amount' should be integer"
        assert isinstance(proof["secret"], str), "'secret' should be string"
        assert isinstance(proof["C"], str), "'C' should be string"
        assert "dleq" not in proof, "proof should not contain 'dleq' field with --no-dleq"


def test_proofs_with_keyset_filter(cli_prefix):
    """Test --keyset flag filters proofs by keyset ID"""
    runner = CliRunner(mix_stderr=False)

    # First create some tokens
    result = runner.invoke(cli, [*cli_prefix, "invoice", "64"])
    assert result.exception is None

    # Verify wallet has balance
    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 64

    # Get all proofs to find a keyset ID
    result_all = runner.invoke(cli, [*cli_prefix, "proofs"])
    assert result_all.exception is None

    import json
    all_proofs = json.loads(result_all.stdout.strip())
    assert len(all_proofs) > 0, "Should have proofs to test keyset filtering"

    # Get a keyset ID from first proof
    test_keyset = all_proofs[0]["id"]

    # Filter by that keyset
    result_filtered = runner.invoke(cli, [*cli_prefix, "proofs", "--keyset", test_keyset])
    assert result_filtered.exception is None
    assert result_filtered.exit_code == 0

    filtered_proofs = json.loads(result_filtered.stdout.strip())
    assert len(filtered_proofs) > 0

    # All filtered proofs should have the same keyset ID
    for proof in filtered_proofs:
        assert proof["id"] == test_keyset, f"proof has wrong keyset ID: {proof['id']} != {test_keyset}"

    # Filter with a non-existent keyset, to make sure nothing is returned
    import secrets
    nonexistent_keyset = '00' + secrets.token_hex(7)  # 16 hex chars (8 bytes)
    result_filtered_again = runner.invoke(cli, [*cli_prefix, "proofs", "--keyset", nonexistent_keyset])
    assert result_filtered_again.exception is None
    assert result_filtered_again.exit_code == 0
    assert "No proofs found for keyset:" in result_filtered_again.stdout


def test_proofs_invalid_keyset(cli_prefix):
    """Test --keyset with non-existent keyset ID"""
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, [*cli_prefix, "proofs", "--keyset", "nonexistent"])

    assert result.exception is None
    assert result.exit_code == 0
    assert "No proofs found for keyset: nonexistent" in result.stdout



def test_proofs_with_all_flag(cli_prefix):
    """Test --all flag includes reserved proofs"""
    runner = CliRunner(mix_stderr=False)

    # Create some tokens first so we have proofs to list
    result = runner.invoke(cli, [*cli_prefix, "invoice", "64"])
    assert result.exit_code == 0

    # Get available proofs (default)
    result_available = runner.invoke(cli, [*cli_prefix, "proofs", "--no-dleq"])
    assert result_available.exception is None

    # Get all proofs (including reserved)
    result_all = runner.invoke(cli, [*cli_prefix, "proofs", "--all", "--no-dleq"])
    assert result_all.exception is None
    assert result_all.exit_code == 0

    import json

    available_proofs = json.loads(result_available.stdout.strip())
    all_proofs = json.loads(result_all.stdout.strip())

    # All proofs should include at least the same number as available proofs
    assert len(all_proofs) >= len(available_proofs), "--all should include at least as many proofs as default"

    print(f"Available proofs: {len(available_proofs)}, All proofs: {len(all_proofs)}")

    # All proofs in available should be in all_proofs
    available_secrets = {proof["secret"] for proof in available_proofs}
    all_secrets = {proof["secret"] for proof in all_proofs}

    assert available_secrets.issubset(all_secrets), "all available proofs should be included in --all"
