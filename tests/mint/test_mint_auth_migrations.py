import pytest

from cashu.core.base import Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.db import Database
from cashu.mint.auth import migrations as auth_migrations
from cashu.mint.auth.crud import AuthLedgerCrudSqlite
from cashu.mint.crud import LedgerCrudSqlite


@pytest.mark.asyncio
async def test_auth_proof_migration_preserves_existing_tokens(tmp_path):
    db = Database("auth", str(tmp_path))
    old_crud = AuthLedgerCrudSqlite()
    shared_crud = LedgerCrudSqlite()

    def proof(secret):
        return Proof(
            id="0011223344556677",
            amount=1,
            secret=secret,
            C=PrivateKey().public_key.format().hex(),
        )

    spent = proof("spent-auth-token")
    pending = proof("pending-auth-token")
    try:
        await auth_migrations.m001_initial(db)
        await old_crud.invalidate_proof(db=db, proof=spent)
        await old_crud.set_proof_pending(db=db, proof=pending)

        await auth_migrations.m006_add_digest_to_auth_proofs(db)
        loaded_spent = await shared_crud.get_proofs_used(db=db, Ys=[spent.Y])
        loaded_pending = await shared_crud.get_proofs_pending(db=db, Ys=[pending.Y])
        assert loaded_spent[0].secret == spent.secret
        assert loaded_spent[0].digest is None
        assert loaded_pending[0].secret == pending.secret
        assert loaded_pending[0].digest is None
        spent_row = await db.fetchone(
            "SELECT c FROM proofs_used WHERE y = :y", {"y": spent.Y}
        )
        pending_row = await db.fetchone(
            "SELECT c FROM proofs_pending WHERE y = :y", {"y": pending.Y}
        )
        assert spent_row and spent_row["c"] == spent.C
        assert pending_row and pending_row["c"] == pending.C

        new_proof = proof("new-auth-token")
        new_proof.digest = "ab" * 32
        await shared_crud.set_proof_pending(db=db, proof=new_proof)
        loaded = await shared_crud.get_proofs_pending(db=db, Ys=[new_proof.Y])
        assert loaded[0].digest == new_proof.digest
        await shared_crud.unset_proof_pending(db=db, proof=new_proof)
        await shared_crud.invalidate_proof(db=db, proof=new_proof)
        loaded = await shared_crud.get_proofs_used(db=db, Ys=[new_proof.Y])
        assert loaded[0].digest == new_proof.digest
    finally:
        await db.engine.dispose()
