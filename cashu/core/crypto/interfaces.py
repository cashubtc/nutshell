from abc import ABC, abstractmethod


class ICashuPublicKey(ABC):
    @abstractmethod
    def format(self, compressed: bool = True) -> bytes: ...
    @abstractmethod
    def serialize(self) -> bytes: ...

class ICashuPrivateKey(ABC):
    @abstractmethod
    def to_hex(self) -> str: ...

PublicKey = ICashuPublicKey
PrivateKey = ICashuPrivateKey
