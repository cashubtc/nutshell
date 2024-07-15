from .secret import Secret
from .crypto.secp import PrivateKey

from typing import List

class DLCSecret:
    secret: str
    blinding_factor: PrivateKey
    derivation_path: str
    all_spending_conditions: List[str]

    def __init__(self, **kwargs):
        self.secret = kwargs['secret']
        self.blinding_factor = kwargs['blinding_factor']
        self.derivation_path = kwargs['derivation_path']
        self.all_spending_conditions = kwargs['all_spending_conditions']
