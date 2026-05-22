from typing import ClassVar as _ClassVar
from typing import Iterable as _Iterable
from typing import Mapping as _Mapping
from typing import Optional as _Optional
from typing import Union as _Union

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf.internal import containers as _containers

DESCRIPTOR: _descriptor.FileDescriptor

class GetInfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class InfoContact(_message.Message):
    __slots__ = ("method", "info")
    METHOD_FIELD_NUMBER: _ClassVar[int]
    INFO_FIELD_NUMBER: _ClassVar[int]
    method: str
    info: str
    def __init__(self, method: _Optional[str] = ..., info: _Optional[str] = ...) -> None: ...

class GetInfoResponse(_message.Message):
    __slots__ = ("name", "pubkey", "version", "description", "long_description", "contact", "motd", "icon_url", "urls", "time", "tos_url")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PUBKEY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    LONG_DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CONTACT_FIELD_NUMBER: _ClassVar[int]
    MOTD_FIELD_NUMBER: _ClassVar[int]
    ICON_URL_FIELD_NUMBER: _ClassVar[int]
    URLS_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    TOS_URL_FIELD_NUMBER: _ClassVar[int]
    name: str
    pubkey: str
    version: str
    description: str
    long_description: str
    contact: _containers.RepeatedCompositeFieldContainer[InfoContact]
    motd: str
    icon_url: str
    urls: _containers.RepeatedScalarFieldContainer[str]
    time: int
    tos_url: str
    def __init__(self, name: _Optional[str] = ..., pubkey: _Optional[str] = ..., version: _Optional[str] = ..., description: _Optional[str] = ..., long_description: _Optional[str] = ..., contact: _Optional[_Iterable[_Union[InfoContact, _Mapping]]] = ..., motd: _Optional[str] = ..., icon_url: _Optional[str] = ..., urls: _Optional[_Iterable[str]] = ..., time: _Optional[int] = ..., tos_url: _Optional[str] = ...) -> None: ...

class UpdateResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class UpdateMotdRequest(_message.Message):
    __slots__ = ("motd",)
    MOTD_FIELD_NUMBER: _ClassVar[int]
    motd: str
    def __init__(self, motd: _Optional[str] = ...) -> None: ...

class UpdateDescriptionRequest(_message.Message):
    __slots__ = ("description",)
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    description: str
    def __init__(self, description: _Optional[str] = ...) -> None: ...

class UpdateIconUrlRequest(_message.Message):
    __slots__ = ("icon_url",)
    ICON_URL_FIELD_NUMBER: _ClassVar[int]
    icon_url: str
    def __init__(self, icon_url: _Optional[str] = ...) -> None: ...

class UpdateNameRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class UpdateUrlRequest(_message.Message):
    __slots__ = ("url",)
    URL_FIELD_NUMBER: _ClassVar[int]
    url: str
    def __init__(self, url: _Optional[str] = ...) -> None: ...

class UpdateContactRequest(_message.Message):
    __slots__ = ("method", "info")
    METHOD_FIELD_NUMBER: _ClassVar[int]
    INFO_FIELD_NUMBER: _ClassVar[int]
    method: str
    info: str
    def __init__(self, method: _Optional[str] = ..., info: _Optional[str] = ...) -> None: ...

class MintMethodOptions(_message.Message):
    __slots__ = ("description",)
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    description: bool
    def __init__(self, description: bool = ...) -> None: ...

class UpdateNut04Request(_message.Message):
    __slots__ = ("unit", "method", "disabled", "min_amount", "max_amount", "options")
    UNIT_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    MIN_AMOUNT_FIELD_NUMBER: _ClassVar[int]
    MAX_AMOUNT_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    unit: str
    method: str
    disabled: bool
    min_amount: int
    max_amount: int
    options: MintMethodOptions
    def __init__(self, unit: _Optional[str] = ..., method: _Optional[str] = ..., disabled: bool = ..., min_amount: _Optional[int] = ..., max_amount: _Optional[int] = ..., options: _Optional[_Union[MintMethodOptions, _Mapping]] = ...) -> None: ...

class MeltMethodOptions(_message.Message):
    __slots__ = ("amountless",)
    AMOUNTLESS_FIELD_NUMBER: _ClassVar[int]
    amountless: bool
    def __init__(self, amountless: bool = ...) -> None: ...

class UpdateNut05Request(_message.Message):
    __slots__ = ("unit", "method", "disabled", "min_amount", "max_amount", "options")
    UNIT_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    MIN_AMOUNT_FIELD_NUMBER: _ClassVar[int]
    MAX_AMOUNT_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    unit: str
    method: str
    disabled: bool
    min_amount: int
    max_amount: int
    options: MeltMethodOptions
    def __init__(self, unit: _Optional[str] = ..., method: _Optional[str] = ..., disabled: bool = ..., min_amount: _Optional[int] = ..., max_amount: _Optional[int] = ..., options: _Optional[_Union[MeltMethodOptions, _Mapping]] = ...) -> None: ...

class UpdateQuoteTtlRequest(_message.Message):
    __slots__ = ("mint_ttl", "melt_ttl")
    MINT_TTL_FIELD_NUMBER: _ClassVar[int]
    MELT_TTL_FIELD_NUMBER: _ClassVar[int]
    mint_ttl: int
    melt_ttl: int
    def __init__(self, mint_ttl: _Optional[int] = ..., melt_ttl: _Optional[int] = ...) -> None: ...

class GetQuoteTtlRequest(_message.Message):
    __slots__ = ("quote_id",)
    QUOTE_ID_FIELD_NUMBER: _ClassVar[int]
    quote_id: str
    def __init__(self, quote_id: _Optional[str] = ...) -> None: ...

class GetQuoteTtlResponse(_message.Message):
    __slots__ = ("expiry",)
    EXPIRY_FIELD_NUMBER: _ClassVar[int]
    expiry: int
    def __init__(self, expiry: _Optional[int] = ...) -> None: ...

class Nut04Quote(_message.Message):
    __slots__ = ("quote", "method", "request", "checking_id", "unit", "amount", "state", "created_time", "paid_time", "expiry", "last_checked", "pubkey", "issued_time")
    QUOTE_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    CHECKING_ID_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CREATED_TIME_FIELD_NUMBER: _ClassVar[int]
    PAID_TIME_FIELD_NUMBER: _ClassVar[int]
    EXPIRY_FIELD_NUMBER: _ClassVar[int]
    LAST_CHECKED_FIELD_NUMBER: _ClassVar[int]
    PUBKEY_FIELD_NUMBER: _ClassVar[int]
    ISSUED_TIME_FIELD_NUMBER: _ClassVar[int]
    quote: str
    method: str
    request: str
    checking_id: str
    unit: str
    amount: int
    state: str
    created_time: int
    paid_time: int
    expiry: int
    last_checked: int
    pubkey: str
    issued_time: int
    def __init__(self, quote: _Optional[str] = ..., method: _Optional[str] = ..., request: _Optional[str] = ..., checking_id: _Optional[str] = ..., unit: _Optional[str] = ..., amount: _Optional[int] = ..., state: _Optional[str] = ..., created_time: _Optional[int] = ..., paid_time: _Optional[int] = ..., expiry: _Optional[int] = ..., last_checked: _Optional[int] = ..., pubkey: _Optional[str] = ..., issued_time: _Optional[int] = ...) -> None: ...

class BlindedMessage(_message.Message):
    __slots__ = ("amount", "id", "B_", "witness")
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    B__FIELD_NUMBER: _ClassVar[int]
    WITNESS_FIELD_NUMBER: _ClassVar[int]
    amount: int
    id: str
    B_: str
    witness: str
    def __init__(self, amount: _Optional[int] = ..., id: _Optional[str] = ..., B_: _Optional[str] = ..., witness: _Optional[str] = ...) -> None: ...

class DLEQ(_message.Message):
    __slots__ = ("e", "s")
    E_FIELD_NUMBER: _ClassVar[int]
    S_FIELD_NUMBER: _ClassVar[int]
    e: str
    s: str
    def __init__(self, e: _Optional[str] = ..., s: _Optional[str] = ...) -> None: ...

class BlindedSignature(_message.Message):
    __slots__ = ("id", "amount", "C_", "dleq")
    ID_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    C__FIELD_NUMBER: _ClassVar[int]
    DLEQ_FIELD_NUMBER: _ClassVar[int]
    id: str
    amount: int
    C_: str
    dleq: DLEQ
    def __init__(self, id: _Optional[str] = ..., amount: _Optional[int] = ..., C_: _Optional[str] = ..., dleq: _Optional[_Union[DLEQ, _Mapping]] = ...) -> None: ...

class Nut05Quote(_message.Message):
    __slots__ = ("quote", "method", "request", "checking_id", "unit", "amount", "fee_reserve", "state", "created_time", "paid_time", "fee_paid", "payment_preimage", "expiry", "outputs", "change")
    QUOTE_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    CHECKING_ID_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    FEE_RESERVE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CREATED_TIME_FIELD_NUMBER: _ClassVar[int]
    PAID_TIME_FIELD_NUMBER: _ClassVar[int]
    FEE_PAID_FIELD_NUMBER: _ClassVar[int]
    PAYMENT_PREIMAGE_FIELD_NUMBER: _ClassVar[int]
    EXPIRY_FIELD_NUMBER: _ClassVar[int]
    OUTPUTS_FIELD_NUMBER: _ClassVar[int]
    CHANGE_FIELD_NUMBER: _ClassVar[int]
    quote: str
    method: str
    request: str
    checking_id: str
    unit: str
    amount: int
    fee_reserve: int
    state: str
    created_time: int
    paid_time: int
    fee_paid: int
    payment_preimage: str
    expiry: int
    outputs: _containers.RepeatedCompositeFieldContainer[BlindedMessage]
    change: _containers.RepeatedCompositeFieldContainer[BlindedSignature]
    def __init__(self, quote: _Optional[str] = ..., method: _Optional[str] = ..., request: _Optional[str] = ..., checking_id: _Optional[str] = ..., unit: _Optional[str] = ..., amount: _Optional[int] = ..., fee_reserve: _Optional[int] = ..., state: _Optional[str] = ..., created_time: _Optional[int] = ..., paid_time: _Optional[int] = ..., fee_paid: _Optional[int] = ..., payment_preimage: _Optional[str] = ..., expiry: _Optional[int] = ..., outputs: _Optional[_Iterable[_Union[BlindedMessage, _Mapping]]] = ..., change: _Optional[_Iterable[_Union[BlindedSignature, _Mapping]]] = ...) -> None: ...

class GetNut04QuoteRequest(_message.Message):
    __slots__ = ("quote_id",)
    QUOTE_ID_FIELD_NUMBER: _ClassVar[int]
    quote_id: str
    def __init__(self, quote_id: _Optional[str] = ...) -> None: ...

class GetNut04QuoteResponse(_message.Message):
    __slots__ = ("quote",)
    QUOTE_FIELD_NUMBER: _ClassVar[int]
    quote: Nut04Quote
    def __init__(self, quote: _Optional[_Union[Nut04Quote, _Mapping]] = ...) -> None: ...

class GetNut05QuoteRequest(_message.Message):
    __slots__ = ("quote_id",)
    QUOTE_ID_FIELD_NUMBER: _ClassVar[int]
    quote_id: str
    def __init__(self, quote_id: _Optional[str] = ...) -> None: ...

class GetNut05QuoteResponse(_message.Message):
    __slots__ = ("quote",)
    QUOTE_FIELD_NUMBER: _ClassVar[int]
    quote: Nut05Quote
    def __init__(self, quote: _Optional[_Union[Nut05Quote, _Mapping]] = ...) -> None: ...

class UpdateQuoteRequest(_message.Message):
    __slots__ = ("quote_id", "state")
    QUOTE_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    quote_id: str
    state: str
    def __init__(self, quote_id: _Optional[str] = ..., state: _Optional[str] = ...) -> None: ...

class RotateNextKeysetRequest(_message.Message):
    __slots__ = ("unit", "max_order", "input_fee_ppk", "final_expiry")
    UNIT_FIELD_NUMBER: _ClassVar[int]
    MAX_ORDER_FIELD_NUMBER: _ClassVar[int]
    INPUT_FEE_PPK_FIELD_NUMBER: _ClassVar[int]
    FINAL_EXPIRY_FIELD_NUMBER: _ClassVar[int]
    unit: str
    max_order: int
    input_fee_ppk: int
    final_expiry: int
    def __init__(self, unit: _Optional[str] = ..., max_order: _Optional[int] = ..., input_fee_ppk: _Optional[int] = ..., final_expiry: _Optional[int] = ...) -> None: ...

class RotateNextKeysetResponse(_message.Message):
    __slots__ = ("id", "unit", "max_order", "input_fee_ppk", "final_expiry")
    ID_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    MAX_ORDER_FIELD_NUMBER: _ClassVar[int]
    INPUT_FEE_PPK_FIELD_NUMBER: _ClassVar[int]
    FINAL_EXPIRY_FIELD_NUMBER: _ClassVar[int]
    id: str
    unit: str
    max_order: int
    input_fee_ppk: int
    final_expiry: int
    def __init__(self, id: _Optional[str] = ..., unit: _Optional[str] = ..., max_order: _Optional[int] = ..., input_fee_ppk: _Optional[int] = ..., final_expiry: _Optional[int] = ...) -> None: ...

class UpdateLightningFeeRequest(_message.Message):
    __slots__ = ("fee_percent", "fee_min_reserve")
    FEE_PERCENT_FIELD_NUMBER: _ClassVar[int]
    FEE_MIN_RESERVE_FIELD_NUMBER: _ClassVar[int]
    fee_percent: float
    fee_min_reserve: int
    def __init__(self, fee_percent: _Optional[float] = ..., fee_min_reserve: _Optional[int] = ...) -> None: ...

class UpdateAuthLimitsRequest(_message.Message):
    __slots__ = ("auth_rate_limit_per_minute", "auth_max_blind_tokens")
    AUTH_RATE_LIMIT_PER_MINUTE_FIELD_NUMBER: _ClassVar[int]
    AUTH_MAX_BLIND_TOKENS_FIELD_NUMBER: _ClassVar[int]
    auth_rate_limit_per_minute: int
    auth_max_blind_tokens: int
    def __init__(self, auth_rate_limit_per_minute: _Optional[int] = ..., auth_max_blind_tokens: _Optional[int] = ...) -> None: ...
