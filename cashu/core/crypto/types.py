from typing import Union

from .bls import PrivateKey as BlsPrivateKey, PublicKey as BlsPublicKey
from .secp import SecpPrivateKey, SecpPublicKey

AnyPrivateKey = Union[SecpPrivateKey, BlsPrivateKey]
AnyPublicKey = Union[SecpPublicKey, BlsPublicKey]
