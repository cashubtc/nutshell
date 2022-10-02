import hashlib
import base64

COIN = 100_000_000
TXID = "bff785da9f8169f49be92fa95e31f0890c385bfb1bd24d6b94d7900057c617ae"

from bitcoin.core import (
    lx,
    COutPoint,
    CMutableTxOut,
    CMutableTxIn,
    CMutableTransaction,
)
from bitcoin.core.script import *
from bitcoin.core.scripteval import VerifyScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret


def step0_carol_privkey():
    """Private key"""
    h = hashlib.sha256(b"correct horse battery staple").digest()
    seckey = CBitcoinSecret.from_secret_bytes(h)
    return seckey


def step0_carolt_checksig_redeemscrip(carol_pubkey):
    """Create script"""
    txin_redeemScript = CScript([carol_pubkey, OP_CHECKSIG])
    # txin_redeemScript = CScript(
    #     [
    #         3,
    #         3,
    #         OP_LESSTHANOREQUAL,
    #         OP_VERIFY,
    #     ]
    # )
    return txin_redeemScript


def step1_carol_create_p2sh_address(txin_redeemScript):
    """Create address (serialized scriptPubKey) to share with Alice"""
    # print("Script:", b2x(txin_redeemScript))
    # returns [OP_HASH160, bitcointx.core.Hash160(self), OP_EQUAL]
    txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
    txin_p2sh_address = CBitcoinAddress.from_scriptPubKey(txin_scriptPubKey)
    # print("Pay to:", str(txin_p2sh_address))
    return txin_p2sh_address


def step1_bob_carol_create_tx(txin_p2sh_address):
    """Create transaction"""
    txid = lx(TXID)
    vout = 0
    txin = CMutableTxIn(COutPoint(txid, vout))
    txout = CMutableTxOut(
        int(0.0005 * COIN),
        CBitcoinAddress(str(txin_p2sh_address)).to_scriptPubKey(),
    )
    tx = CMutableTransaction([txin], [txout])
    return tx, txin


def step2_carol_sign_tx(txin_redeemScript):
    """Sign transaction with private key"""
    seckey = step0_carol_privkey()
    txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
    tx, txin = step1_bob_carol_create_tx(txin_p2sh_address)
    sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)
    sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
    txin.scriptSig = CScript([sig, txin_redeemScript])
    return txin


def step3_bob_verify_script(txin_signature, txin_redeemScript):
    txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()

    try:
        VerifyScript(txin_signature, txin_scriptPubKey, tx, 0)
        return True
    except Exception as e:
        print(e)
        return False


if __name__ == "__main__":
    # https://github.com/romanz/python-bitcointx/blob/master/examples/spend-p2sh-txout.py
    # CAROL shares txin_p2sh_address with ALICE:

    # ---------
    # CAROL defines scripthash and ALICE mints them

    txin_redeemScript = step0_carolt_checksig_redeemscrip(step0_carol_privkey().pub)
    txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
    print(f"Carol sends Alice secret = P2SH:{txin_p2sh_address}")
    print("")

    # ---------

    # ALICE: mint tokens with secret SCRIPT:txin_p2sh_address
    print(f"Alice mints tokens with secret = P2SH:{txin_p2sh_address}")
    print("")
    # ...

    # ---------
    # CAROL redeems with MINT

    # CAROL PRODUCES txin_redeemScript and txin_signature to send to MINT
    txin_redeemScript = step0_carolt_checksig_redeemscrip(step0_carol_privkey().pub)
    txin_signature = step2_carol_sign_tx(txin_redeemScript).scriptSig

    txin_redeemScript_b64 = base64.urlsafe_b64encode(txin_redeemScript).decode()
    txin_signature_b64 = base64.urlsafe_b64encode(txin_signature).decode()
    print(
        f"Carol to Bob:\nscript: {txin_redeemScript_b64}\nsignature: {txin_signature_b64}\n"
    )
    print("")
    # ---------
    # MINT verifies SCRIPT and SIGNATURE and mints tokens

    # MINT receives txin_redeemScript_b64 and txin_signature_b64 fom CAROL:
    txin_redeemScript = CScript(base64.urlsafe_b64decode(txin_redeemScript_b64))
    txin_signature = CScript(base64.urlsafe_b64decode(txin_signature_b64))

    txin_p2sh_address = step1_carol_create_p2sh_address(txin_redeemScript)
    print(f"Bob recreates secret: P2SH:{txin_p2sh_address}")
    # MINT checks that SCRIPT:txin_p2sh_address has not been spent yet
    # ...
    tx, _ = step1_bob_carol_create_tx(txin_p2sh_address)

    print(
        f"Bob verifies:\nscript: {txin_redeemScript_b64}\nsignature: {txin_signature_b64}\n"
    )
    script_valid = step3_bob_verify_script(txin_signature, txin_redeemScript)
    # MINT redeems tokens and stores SCRIPT:txin_p2sh_address
    # ...

    print("Successfull.")
    # print("Transaction:", b2x(tx.serialize()))
