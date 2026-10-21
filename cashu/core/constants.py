# Maximum lengths for Pydantic string fields
MAX_UNIT_LEN = 64
MAX_PUBKEY_LEN = 66
MAX_KEYSET_ID_LEN = 66  # Version byte followed by a 32-byte hash, hex-encoded
MAX_SCALAR_LEN = 64  # 32-byte scalar, hex-encoded
MAX_SIG_LEN = 130
MAX_QUOTE_ID_LEN = 256
MAX_INVOICE_DESC_LEN = 1024
MAX_PAYMENT_REQUEST_LEN = 10000
