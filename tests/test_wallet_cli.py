import asyncio
import base64
import json
from typing import Tuple

import pytest
from click.testing import CliRunner

from cashu.core.base import TokenV3
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from cashu.wallet.wallet import Wallet
from tests.helpers import is_fake, pay_if_regtest


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


async def init_wallet():
    settings.debug = False
    wallet = await Wallet.with_db(
        url=settings.mint_url,
        db="test_data/test_cli_wallet",
        name="wallet",
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
    assert f"Balance: {w.available_balance} sat" in result.output
    assert result.exit_code == 0


@pytest.mark.skipif(not is_fake, reason="only on fakewallet")
def test_invoice_automatic_fakewallet(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000"],
    )
    assert result.exception is None
    print("INVOICE")
    print(result.output)
    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert f"Balance: {wallet.available_balance} sat" in result.output
    assert result.exit_code == 0


def test_invoice(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "-n", "1000"],
    )

    assert result.exception is None

    invoice, invoice_id = get_bolt11_and_invoice_id_from_invoice_command(result.output)
    pay_if_regtest(invoice)

    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "1000", "--id", invoice_id],
    )
    assert result.exception is None

    wallet = asyncio.run(init_wallet())
    assert wallet.available_balance >= 1000
    assert result.exit_code == 0


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
    pay_if_regtest(invoice)
    result = runner.invoke(
        cli,
        [*cli_prefix, "invoice", "10", "-s", "1", "--id", invoice_id],
    )
    assert result.exception is None

    assert result.exception is None
    wallet = asyncio.run(init_wallet())
    assert wallet.proof_amounts.count(1) >= 10


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
        assert "test_cli_wallet" in result.output
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
    assert "cashuA" in token_str, "output does not have a token"
    token = TokenV3.deserialize(token_str)
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
    assert "cashuA" in token_str, "output does not have a token"
    token = TokenV3.deserialize(token_str)
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
    token_str = result.output.split("\n")[4]
    assert token_str.startswith("eyJwcm9v"), "output is not as expected"


def test_send_without_split(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "2", "--nosplit"],
    )
    assert result.exception is None
    print("SEND")
    print("test_send_without_split", result.output)
    assert "cashuA" in result.output, "output does not have a token"


def test_send_without_split_but_wrong_amount(mint, cli_prefix):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [*cli_prefix, "send", "10", "--nosplit"],
    )
    assert "No proof with this amount found" in str(result.exception)


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


def test_receive_tokenv3_no_mint(mint, cli_prefix):
    # this test works only if the previous test succeeds because we simulate the case
    # where the mint URL is not in the token therefore, we need to know the mint keyset
    # already and have the mint URL in the db
    runner = CliRunner()
    token_dict = {
        "token": [
            {
                "proofs": [
                    {
                        "id": "009a1f293253e41e",
                        "amount": 2,
                        "secret": "ea3420987e1ecd71de58e4ff00e8a94d1f1f9333dad98e923e3083d21bf314e2",
                        "C": "0204eb99cf27105b4de4029478376d6f71e9e3d5af1cc28a652c028d1bcd6537cc",
                    },
                    {
                        "id": "009a1f293253e41e",
                        "amount": 8,
                        "secret": "3447975db92f43b269290e05b91805df7aa733f622e55d885a2cab78e02d4a72",
                        "C": "0286c78750d414bc067178cbac0f3551093cea47d213ebf356899c972448ee6255",
                    },
                ]
            }
        ]
    }
    token = "cashuA" + base64.b64encode(json.dumps(token_dict).encode()).decode()
    print("RECEIVE")
    print(token)
    result = runner.invoke(
        cli,
        [
            *cli_prefix,
            "receive",
            token,
        ],
    )
    assert result.exception is None
    print(result.output)


def test_receive_tokenv2(mint, cli_prefix):
    runner = CliRunner()
    token_dict = {
        "proofs": [
            {
                "id": "009a1f293253e41e",
                "amount": 2,
                "secret": (
                    "a1efb610726b342aec209375397fee86a0b88732779ce218e99132f9a975db2a"
                ),
                "C": (
                    "03057e5fe352bac785468ffa51a1ecf0f75af24d2d27ab1fd00164672a417d9523"
                ),
            },
            {
                "id": "009a1f293253e41e",
                "amount": 8,
                "secret": (
                    "b065a17938bc79d6224dc381873b8b7f3a46267e8b00d9ce59530354d9d81ae4"
                ),
                "C": (
                    "021e83773f5eb66f837a5721a067caaa8d7018ef0745b4302f4e2c6cac8806dc69"
                ),
            },
        ],
        "mints": [{"url": "http://localhost:3337", "ids": ["009a1f293253e41e"]}],
    }
    token = base64.b64encode(json.dumps(token_dict).encode()).decode()
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
    )
    assert result.exception is None
    print("RECEIVE")
    print(result.output)


def test_receive_tokenv1(mint, cli_prefix):
    runner = CliRunner()
    token_dict = [
        {
            "id": "009a1f293253e41e",
            "amount": 2,
            "secret": (
                "bc0360c041117969ef7b8add48d0981c669619aa5743cccce13d4a771c9e164d"
            ),
            "C": "026fd492f933e9240f36fb2559a7327f47b3441b895a5f8f0b1d6825fee73438f0",
        },
        {
            "id": "009a1f293253e41e",
            "amount": 8,
            "secret": (
                "cf83bd8df35bb104d3818511c1653e9ebeb2b645a36fd071b2229aa2c3044acd"
            ),
            "C": "0279606f3dfd7784757c6320b17e1bf2211f284318814c12bfaa40680e017abd34",
        },
    ]
    token = base64.b64encode(json.dumps(token_dict).encode()).decode()
    result = runner.invoke(
        cli,
        [*cli_prefix, "receive", token],
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
