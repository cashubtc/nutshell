# Plan: Cryptographic Key Type Hierarchy Redesign

This document outlines the strategy for resolving persistent `mypy` invariance errors by refactoring the cryptographic key types (`PublicKey` and `PrivateKey`) from `Union` types into a formal inheritance-based type hierarchy.

## 1. Problem Statement
Currently, we represent public/private keys as a `Union` of SECP and BLS types. This leads to `mypy` invariance errors because `List[SecpPublicKey]` is **not** a subtype of `List[Union[SecpPublicKey, BlsPublicKey]]`. While `Union` types solve type *definition* issues, they do not resolve *collection* variance issues, necessitating excessive `type: ignore` comments.

## 2. Objective
Introduce a common abstract base interface for all cryptographic keys in Nutshell. This allows collections to be typed as `List[BasePublicKey]`, which can safely accept instances of both `SecpPublicKey` and `BlsPublicKey`, removing the need for `type: ignore`.

## 3. Proposed Hierarchy

We will introduce `ABC`s (Abstract Base Classes) for Public and Private keys.

```python
# cashu/core/crypto/interfaces.py

from abc import ABC, abstractmethod

class ICashuPublicKey(ABC):
    @abstractmethod
    def format(self, compressed: bool = True) -> bytes: ...
    @abstractmethod
    def serialize(self) -> bytes: ...

class ICashuPrivateKey(ABC):
    @abstractmethod
    def to_hex(self) -> str: ...
```

## 4. Implementation Strategy

### Phase 1: Define Interfaces
*   Create `cashu/core/crypto/interfaces.py` defining `ICashuPublicKey` and `ICashuPrivateKey`.
*   Ensure these ABCs define all shared methods currently used across the codebase (`format`, `serialize`, `to_hex`, etc.).

### Phase 2: Refactor Concrete Implementations
*   Update `cashu/core/crypto/secp.py` and `cashu/core/crypto/bls.py` so the concrete classes (`SecpPublicKey`, `BlsPublicKey`, etc.) inherit from the new interfaces.
*   *Note:* If the underlying library classes (e.g., `coincurve.PublicKey`) cannot directly inherit from the ABC, use an adapter/wrapper class approach.

### Phase 3: Update Core Base
*   Modify `cashu/core/base.py` to remove `AnyPublicKey` and `AnyPrivateKey` union types.
*   Update `PublicKey` and `PrivateKey` to refer to the new ABCs.

### Phase 4: Systematic Component Refactor
Refactor component-by-component to replace `Union` type signatures with the ABCs:
1.  **Ledger/Mint Logic:** Update `mint/ledger.py` and `mint/verification.py`.
2.  **Wallet Logic:** Update `wallet/wallet.py` and `wallet/secrets.py`.
3.  **Auth/Protocols:** Update `wallet/auth/` and any interfaces.

### Phase 5: Cleanup
*   Perform a global find/replace to remove `# type: ignore` comments that were added to handle the invariance issues.
*   Run `make mypy` and fix remaining structural type mismatches.

## 5. Risks and Mitigations

| Risk | Mitigation |
| :--- | :--- |
| **Breaking changes in concrete key implementations** | Keep the new ABCs thin. Ensure they only define contract-critical methods; do not force logic into the ABC. |
| **Serialization issues** | Ensure the `format()` and `serialize()` methods in the ABC are strictly implemented by concrete classes to match existing hex/bytes formats. |
| **Performance overhead** | If using wrapper classes, measure overhead. If using direct inheritance/mixin, the overhead should be negligible. |

## 6. Next Steps
1.  Review and approve the proposed interface definition in `interfaces.py`.
2.  Begin Phase 2 for one cryptographic implementation (`secp.py`) as a prototype.
3.  Evaluate the impact on `mypy` errors before proceeding to Phase 4.
