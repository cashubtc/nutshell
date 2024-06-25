from abc import ABC, abstractmethod

from pydantic import BaseModel

from ...core.json_rpc.base import JSONRPCSubscriptionKinds


class LedgerEvent(ABC, BaseModel):
    """AbstractBaseClass for BaseModels that can be sent to the
    LedgerEventManager for broadcasting subscription events to clients.
    """

    @property
    @abstractmethod
    def identifier(self) -> str:
        pass

    @property
    @abstractmethod
    def kind(self) -> JSONRPCSubscriptionKinds:
        pass
