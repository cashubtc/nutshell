"""NUT-10 signing packages and spend receipts."""

import base64
import hashlib
from typing import Annotated, ClassVar, Dict, List, Literal, Mapping, Optional, Sequence

from coincurve import PublicKeyXOnly
from pydantic import BaseModel, ConfigDict, Field

from ..base import Proof, ProofSpentState, ProofState, TokenV3, TokenV4
from ..crypto.bls_dhke import hash_to_curve, secret_to_hash_input
from ..crypto.keys import is_bls_keyset
from ..crypto.nutroot import (
    NutrootControlBlock,
    NutrootWitness,
    keyset_id_transcript_bytes,
    minimal_be,
    parse_nutroot_leaf,
    verify_nutroot_commitment,
    verify_nutroot_witness,
)
from ..crypto.secp import PrivateKey, PublicKey
from ..crypto.transcript import (
    TranscriptContainer,
    input_digest,
    parse_transaction_transcript,
    spend_commitment,
)
from ..nutroot import _key_variants
from ..p2bk import derive_blinding_scalar, ecdh_shared_secret


class NutrootArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)
    prefix: ClassVar[str]

    def serialize(self) -> str:
        raw = self.model_dump_json(by_alias=True, exclude_none=True).encode()
        return self.prefix + base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def deserialize(cls, encoded: str):
        if not encoded.startswith(cls.prefix):
            raise ValueError("Unexpected Nutroot artifact prefix")
        raw = encoded[len(cls.prefix) :]
        decoded = base64.b64decode(
            raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True
        )
        return cls.model_validate_json(decoded)


class SigningSpend(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)
    input_index: int = Field(alias="input", ge=0)
    secret: str
    leaf: str
    control: NutrootControlBlock
    E: Optional[str] = None
    slots: Optional[List[Annotated[int, Field(ge=1, le=255)]]] = None
    signatures: List[str] = Field(default_factory=list)


class SigningPackage(NutrootArtifact):
    prefix: ClassVar[str] = "nutspA"
    version: Literal["nutspA"] = "nutspA"
    transcript: str
    spends: List[SigningSpend] = Field(min_length=1)

    def contexts(self) -> Dict[int, bytes]:
        raw = bytes.fromhex(self.transcript)
        containers = parse_transaction_transcript(raw)
        digest = hashlib.sha256(raw).digest()
        contexts: Dict[int, bytes] = {}
        for spend in self.spends:
            if spend.input_index in contexts or spend.input_index >= len(containers):
                raise ValueError("Signing package repeats or misidentifies an input")
            container = containers[spend.input_index]
            secret = secret_to_hash_input(spend.secret)
            if container.type == 0x11:
                if hash_to_curve(secret).format() != container.fields[3]:
                    raise ValueError(
                        "Signing package secret does not name this proof input"
                    )
            elif container.type == 0x12:
                if secret != container.fields[3]:
                    raise ValueError(
                        "Signing package secret does not name this quote input"
                    )
            else:
                raise ValueError("Signing package names an output as an input")
            leaf_bytes = bytes.fromhex(spend.leaf)
            leaf = parse_nutroot_leaf(leaf_bytes)
            if leaf.type == "commit":
                raise ValueError("Commit leaf is not a signing path")
            if not verify_nutroot_commitment(
                PublicKey(secret),
                PublicKey(bytes.fromhex(spend.control.internal_key)),
                leaf_bytes,
                [bytes.fromhex(node) for node in spend.control.path],
            ):
                raise ValueError("Signing package leaf does not commit to its secret")
            message = input_digest(digest, container.record)
            if len(spend.signatures) > len(leaf.keys):
                raise ValueError("Signing package has more signatures than leaf keys")
            for signature in spend.signatures:
                encoded = bytes.fromhex(signature)
                if len(encoded) != 64 or not any(
                    PublicKeyXOnly(key.format()[1:]).verify(encoded, message)
                    for key in leaf.keys
                ):
                    raise ValueError(
                        "Signing package contains an invalid partial signature"
                    )
            if spend.E is not None:
                if len(bytes.fromhex(spend.E)) != 33:
                    raise ValueError("Signing ephemeral must be compressed")
                PublicKey(bytes.fromhex(spend.E))
            contexts[spend.input_index] = message
        return contexts

    def sign(self, private_keys: Sequence[PrivateKey]) -> "SigningPackage":
        messages = self.contexts()
        signed = self.model_copy(deep=True)
        variants = _key_variants(private_keys)
        for spend in signed.spends:
            leaf = parse_nutroot_leaf(bytes.fromhex(spend.leaf))
            listed = {key.format() for key in leaf.keys}
            candidates = {key.public_key.format(): key for key in variants}
            if spend.E is not None:
                ephemeral = PublicKey(bytes.fromhex(spend.E))
                for key in variants:
                    shared = ecdh_shared_secret(ephemeral, key)
                    for slot in range(1, 256):
                        candidate = key.add(
                            derive_blinding_scalar(shared, slot).to_bytes(32, "big")
                        )
                        if candidate.public_key.format() in listed:
                            candidates[candidate.public_key.format()] = candidate
            message = messages[spend.input_index]
            for public in leaf.keys:
                if any(
                    PublicKeyXOnly(public.format()[1:]).verify(
                        bytes.fromhex(sig), message
                    )
                    for sig in spend.signatures
                ):
                    continue
                signing_key = candidates.get(public.format())
                if signing_key is not None:
                    spend.signatures.append(signing_key.sign_schnorr(message).hex())
        signed.contexts()
        return signed

    def merge(
        self,
        others: Sequence["SigningPackage"],
        *,
        expected_transcript: bytes,
        preimages: Mapping[int, bytes] = {},
        now: Optional[float] = None,
    ) -> Dict[int, str]:
        """Merge signatures only into the transaction the creator reviewed."""
        if bytes.fromhex(self.transcript) != expected_transcript:
            raise ValueError("Signing package belongs to a different transaction")
        messages = self.contexts()
        merged = self.model_copy(deep=True)
        by_input = {spend.input_index: spend for spend in merged.spends}
        for other in others:
            if bytes.fromhex(other.transcript) != expected_transcript:
                raise ValueError("Signing package belongs to a different transaction")
            other.contexts()
            for spend in other.spends:
                expected = by_input.get(spend.input_index)
                if expected is None or expected.model_dump(
                    exclude={"signatures"}
                ) != spend.model_dump(exclude={"signatures"}):
                    raise ValueError("Signing package changes the requested spend")
                expected.signatures = list(
                    dict.fromkeys([*expected.signatures, *spend.signatures])
                )
        witnesses: Dict[int, str] = {}
        for index, spend in by_input.items():
            leaf = parse_nutroot_leaf(bytes.fromhex(spend.leaf))
            signatures: List[str] = []
            message = messages[index]
            for key in leaf.keys:
                signature = next(
                    (
                        signature
                        for signature in spend.signatures
                        if PublicKeyXOnly(key.format()[1:]).verify(
                            bytes.fromhex(signature), message
                        )
                    ),
                    None,
                )
                if signature is not None:
                    signatures.append(signature)
            preimage = preimages.get(index)
            witness = NutrootWitness(
                signatures=signatures[: leaf.n],
                leaf=spend.leaf,
                control=spend.control,
                preimage=preimage.hex() if preimage is not None else None,
            ).model_dump_json(by_alias=True, exclude_none=True)
            verify_nutroot_witness(
                PublicKey(bytes.fromhex(spend.secret)), message, witness, now=now
            )
            witnesses[index] = witness
        return witnesses


class ReceiptEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)
    Y: str
    keyset_id: str = Field(alias="keysetId")
    input_digest: str = Field(alias="inputDigest")
    witness: str
    commitment: str
    transcript: str


def _proof_record(
    proof: Proof, containers: Sequence[TranscriptContainer]
) -> TranscriptContainer:
    expected = {
        1: minimal_be(proof.amount),
        2: keyset_id_transcript_bytes(proof.id),
        3: bytes.fromhex(proof.Y),
        4: bytes.fromhex(proof.C),
    }
    record = next(
        (
            container
            for container in containers
            if container.type == 0x11 and container.fields == expected
        ),
        None,
    )
    if record is None:
        raise ValueError("Receipt proof is absent from its transaction transcript")
    return record


class SpendReceipt(NutrootArtifact):
    prefix: ClassVar[str] = "nutrcA"
    token: str
    receipts: List[ReceiptEntry] = Field(min_length=1)

    def verify_states(
        self, states: Sequence[ProofState], *, now: Optional[float] = None
    ) -> None:
        """Verify against exact mint-published witnesses or remote commitments."""
        commitments = {}
        for state in states:
            if state.state != ProofSpentState.spent:
                raise ValueError("Receipt requires a SPENT proof state")
            if state.Y in commitments:
                raise ValueError("Receipt states repeat a proof")
            if state.witness is not None and state.input_digest is not None:
                commitments[state.Y] = spend_commitment(
                    bytes.fromhex(state.Y),
                    bytes.fromhex(state.input_digest),
                    state.witness,
                ).hex()
            elif state.commitment is not None:
                commitments[state.Y] = state.commitment
            else:
                raise ValueError("Proof state has no Nutroot spend evidence")
        self.verify(commitments, now=now)

    def verify(
        self, mint_commitments: Mapping[str, str], *, now: Optional[float] = None
    ) -> None:
        token = (
            TokenV4.deserialize(self.token)
            if self.token.startswith("cashuB")
            else TokenV3.deserialize(self.token)
        )
        token_proofs = [proof for proof in token.proofs if is_bls_keyset(proof.id)]
        proofs = {proof.Y: proof for proof in token_proofs}
        if len(proofs) != len(token_proofs):
            raise ValueError("Receipt token repeats a proof")
        if len(proofs) != len(self.receipts) or {
            entry.Y for entry in self.receipts
        } != set(proofs):
            raise ValueError("Receipt entries must cover exactly the token's v3 proofs")
        for entry in self.receipts:
            proof = proofs[entry.Y]
            if not is_bls_keyset(entry.keyset_id) or len(entry.keyset_id) != 66:
                raise ValueError("Receipt needs a full v3 keyset ID")
            if proof.id != entry.keyset_id and (
                len(proof.id) != 16 or not entry.keyset_id.startswith(proof.id)
            ):
                raise ValueError("Receipt keyset differs from the token")
            proof = proof.model_copy(update={"id": entry.keyset_id})
            transcript = bytes.fromhex(entry.transcript)
            record = _proof_record(proof, parse_transaction_transcript(transcript))
            message = input_digest(hashlib.sha256(transcript).digest(), record.record)
            if message.hex() != entry.input_digest:
                raise ValueError("Receipt input digest differs from the transcript")
            commitment = spend_commitment(
                bytes.fromhex(entry.Y), message, entry.witness
            ).hex()
            if (
                commitment != entry.commitment
                or mint_commitments.get(entry.Y) != commitment
            ):
                raise ValueError("Receipt does not open the mint's spend commitment")
            verify_nutroot_witness(
                PublicKey(bytes.fromhex(proof.secret)), message, entry.witness, now=now
            )

    @classmethod
    def create(
        cls, token: TokenV4, transcript: bytes, proofs: Sequence[Proof]
    ) -> "SpendReceipt":
        containers = parse_transaction_transcript(transcript)
        digest = hashlib.sha256(transcript).digest()
        entries = []
        for proof in proofs:
            if not is_bls_keyset(proof.id):
                continue
            if proof.witness is None:
                raise ValueError("Spent proof needs its exact witness")
            message = input_digest(digest, _proof_record(proof, containers).record)
            entries.append(
                ReceiptEntry(
                    Y=proof.Y,
                    keysetId=proof.id,
                    inputDigest=message.hex(),
                    witness=proof.witness,
                    commitment=spend_commitment(
                        bytes.fromhex(proof.Y), message, proof.witness
                    ).hex(),
                    transcript=transcript.hex(),
                )
            )
        receipt = cls(token=token.serialize(), receipts=entries)
        receipt.verify({entry.Y: entry.commitment for entry in entries})
        return receipt
