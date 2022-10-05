import base64
import hashlib
import random

COIN = 100_000_000
TXID = "bff785da9f8169f49be92fa95e31f0890c385bfb1bd24d6b94d7900057c617ae"
SEED = b"__not__used"

from bitcoin.core import CMutableTxIn, CMutableTxOut, COutPoint, CTransaction, lx
from bitcoin.core.script import *
from bitcoin.core.script import CScript
from bitcoin.core.scripteval import (
    SCRIPT_VERIFY_P2SH,
    EvalScriptError,
    VerifyScript,
    VerifyScriptError,
)
from bitcoin.wallet import CBitcoinSecret, P2SHBitcoinAddress


def step0_carol_privkey():
    """Private key"""
    # h = hashlib.sha256(SEED).digest()
    h = hashlib.sha256(str(random.getrandbits(256)).encode()).digest()
    seckey = CBitcoinSecret.from_secret_bytes(h)
    return seckey


def step0_carol_checksig_redeemscrip(carol_pubkey):
    """Create script"""
    txin_redeemScript = CScript([carol_pubkey, OP_CHECKSIG])
    # txin_redeemScript = CScript([-123, OP_CHECKLOCKTIMEVERIFY])
    # txin_redeemScript = CScript([3, 3, OP_LESSTHAN, OP_VERIFY])
    return txin_redeemScript


def step1_carol_create_p2sh_address(txin_redeemScript):
    """Create address (serialized scriptPubKey) to share with Alice"""
    txin_p2sh_address = P2SHBitcoinAddress.from_redeemScript(txin_redeemScript)
    return txin_p2sh_address


def step1_bob_carol_create_tx(txin_p2sh_address):
    """Create transaction"""
    txid = lx(TXID)
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    txout = CMutableTxOut(
        int(0.0005 * COIN),
        P2SHBitcoinAddress(str(txin_p2sh_address)).to_scriptPubKey(),
    )
    tx = CTransaction([txin], [txout])
    return tx, txin


def step2_carol_sign_tx(txin_redeemScript, privatekey):
    """Sign transaction with private key"""
    txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
    tx, txin = step1_bob_carol_create_tx(txin_p2sh_address)
    sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)
    sig = privatekey.sign(sighash) + bytes([SIGHASH_ALL])
    txin.scriptSig = CScript([sig, txin_redeemScript])
    return txin


def step3_bob_verify_script(txin_signature, txin_redeemScript, tx):
    txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
    try:
        VerifyScript(
            txin_signature, txin_scriptPubKey, tx, 0, flags=[SCRIPT_VERIFY_P2SH]
        )
        return True
    except VerifyScriptError as e:
        raise Exception("Script verification failed:", e)
    except EvalScriptError as e:
        print(f"Script: {txin_scriptPubKey.__repr__()}")
        raise Exception("Script evaluation failed:", e)
    except Exception as e:
        raise Exception("Script execution failed:", e)


def verify_script(txin_redeemScript_b64, txin_signature_b64):
    txin_redeemScript = CScript(base64.urlsafe_b64decode(txin_redeemScript_b64))
    print("Redeem script:", txin_redeemScript.__repr__())
    # txin_redeemScript = CScript([2, 3, OP_LESSTHAN, OP_VERIFY])
    txin_signature = CScript(value=base64.urlsafe_b64decode(txin_signature_b64))

    txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
    print(f"Bob recreates secret: P2SH:{txin_p2sh_address}")
    # MINT checks that P2SH:txin_p2sh_address has not been spent yet
    # ...
    tx, _ = step1_bob_carol_create_tx(txin_p2sh_address)

    print(
        f"Bob verifies:\nscript: {txin_redeemScript_b64}\nsignature: {txin_signature_b64}\n"
    )
    script_valid = step3_bob_verify_script(txin_signature, txin_redeemScript, tx)
    # MINT redeems tokens and stores P2SH:txin_p2sh_address
    # ...
    if script_valid:
        print("Successfull.")
    else:
        print("Error.")
    return txin_p2sh_address, script_valid


# simple test case
if __name__ == "__main__":
    # https://github.com/romanz/python-bitcointx/blob/master/examples/spend-p2sh-txout.py
    # CAROL shares txin_p2sh_address with ALICE:

    # ---------
    # CAROL defines scripthash and ALICE mints them
    alice_privkey = step0_carol_privkey()
    txin_redeemScript = step0_carol_checksig_redeemscrip(alice_privkey.pub)
    print("Script:", txin_redeemScript.__repr__())
    txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
    print(f"Carol sends Alice secret = P2SH:{txin_p2sh_address}")
    print("")

    # ---------

    # ALICE: mint tokens with secret P2SH:txin_p2sh_address
    print(f"Alice mints tokens with secret = P2SH:{txin_p2sh_address}")
    print("")
    # ...

    # ---------
    # CAROL redeems with MINT

    # CAROL PRODUCES txin_redeemScript and txin_signature to send to MINT
    txin_redeemScript = step0_carol_checksig_redeemscrip(alice_privkey.pub)
    txin_signature = step2_carol_sign_tx(txin_redeemScript, alice_privkey).scriptSig

    txin_redeemScript_b64 = base64.urlsafe_b64encode(txin_redeemScript).decode()
    txin_signature_b64 = base64.urlsafe_b64encode(txin_signature).decode()
    print(
        f"Carol to Bob:\nscript: {txin_redeemScript.__repr__()}\nscript: {txin_redeemScript_b64}\nsignature: {txin_signature_b64}\n"
    )
    print("")
    # ---------
    # MINT verifies SCRIPT and SIGNATURE and mints tokens

    # MINT receives txin_redeemScript_b64 and txin_signature_b64 fom CAROL:
    txin_redeemScript = CScript(base64.urlsafe_b64decode(txin_redeemScript_b64))
    txin_redeemScript_p2sh = txin_p2sh_address.to_redeemScript()
    print("Redeem script:", txin_redeemScript.__repr__())
    print("P2SH:", txin_redeemScript_p2sh.__repr__())
    # txin_redeemScript = CScript([2, 3, OP_LESSTHAN, OP_VERIFY])
    txin_signature = CScript(value=base64.urlsafe_b64decode(txin_signature_b64))

    txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
    print(f"Bob recreates secret: P2SH:{txin_p2sh_address}")
    # MINT checks that P2SH:txin_p2sh_address has not been spent yet
    # ...
    tx, _ = step1_bob_carol_create_tx(txin_p2sh_address)

    print(
        f"Bob verifies:\nscript: {txin_redeemScript_b64}\nsignature: {txin_signature_b64}\n"
    )
    script_valid = step3_bob_verify_script(txin_signature, txin_redeemScript, tx)
    # MINT redeems tokens and stores P2SH:txin_p2sh_address
    # ...
    if script_valid:
        print("Successfull.")
    else:
        print("Error.")
