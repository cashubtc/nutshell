from .secret import Secret
from ..base import DLCWitness
from ..core.crypto.secp import PrivateKey

class DLCSecret:
    secret: Secret
    witness: DLCWitness
    blinding_factor: PrivateKey
    derivation_path: str

    def __init__(self, **kwargs):
        self.secret = kwargs['secret']
        self.witness = kwargs['witness']
        self.blinding_factor = kwargs['blinding_factor']
        self.derivation_path = kwargs['derivation_path']
