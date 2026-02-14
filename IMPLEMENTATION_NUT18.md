# NUT-18 Implementation Plan

## Goal
Implement the core data structures and serialization logic for [NUT-18 (Payment Requests)](../../nuts/18.md).

## Task List

- [ ] **Define Data Models**: Create `cashu/core/nuts/nut18.py`
    - [ ] `Transport` class (with `t`, `a`, `g` fields)
    - [ ] `NUT10Option` class (with `k`, `d`, `t` fields)
    - [ ] `PaymentRequest` class (with `i`, `a`, `u`, `s`, `m`, `d`, `t`, `nut10` fields)
    - [ ] `PaymentRequestPayload` class (for the response payload)

- [ ] **Serialization Logic**
    - [ ] `serialize()`: Object -> CBOR -> Base64UrlSafe -> `creqA...`
    - [ ] `deserialize(creq_str)`: `creqA...` -> Base64UrlSafe -> CBOR -> Object

- [ ] **Tests**
    - [ ] `tests/core/test_nut18.py`: Unit tests matching spec examples.
