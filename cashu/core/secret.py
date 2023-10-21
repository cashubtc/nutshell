import json
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from loguru import logger
from pydantic import BaseModel

from .crypto.secp import PrivateKey


class SecretKind(Enum):
    P2PK = "P2PK"
    HTLC = "HTLC"


class Tags(BaseModel):
    """
    Tags are used to encode additional information in the Secret of a Proof.
    """

    __root__: List[List[str]] = []

    def __init__(self, tags: Optional[List[List[str]]] = None, **kwargs):
        super().__init__(**kwargs)
        self.__root__ = tags or []

    def __setitem__(self, key: str, value: Union[str, List[str]]) -> None:
        if isinstance(value, str):
            self.__root__.append([key, value])
        elif isinstance(value, list):
            self.__root__.append([key, *value])

    def __getitem__(self, key: str) -> Union[str, None]:
        return self.get_tag(key)

    def get_tag(self, tag_name: str) -> Union[str, None]:
        for tag in self.__root__:
            if tag[0] == tag_name:
                return tag[1]
        return None

    def get_tag_all(self, tag_name: str) -> List[str]:
        all_tags = []
        for tag in self.__root__:
            if tag[0] == tag_name:
                for t in tag[1:]:
                    all_tags.append(t)
        return all_tags


class Secret(BaseModel):
    """Describes spending condition encoded in the secret field of a Proof."""

    kind: str
    data: str
    tags: Tags
    nonce: Union[None, str] = None

    def serialize(self) -> str:
        data_dict: Dict[str, Any] = {
            "data": self.data,
            "nonce": self.nonce or PrivateKey().serialize()[:32],
        }
        if self.tags.__root__:
            logger.debug(f"Serializing tags: {self.tags.__root__}")
            data_dict["tags"] = self.tags.__root__
        return json.dumps(
            [self.kind, data_dict],
        )

    @classmethod
    def deserialize(cls, from_proof: str):
        kind, kwargs = json.loads(from_proof)
        data = kwargs.pop("data")
        nonce = kwargs.pop("nonce")
        tags_list: List = kwargs.pop("tags", None)
        tags = Tags(tags=tags_list)
        logger.debug(f"Deserialized Secret: {kind}, {data}, {nonce}, {tags}")
        return cls(kind=kind, data=data, nonce=nonce, tags=tags)
