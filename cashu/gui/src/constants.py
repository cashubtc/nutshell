from enum import IntEnum


class TransactionType(IntEnum):
    TOKEN = 0
    LIGHTNING = 1
    NOSTR_KEY = 2
