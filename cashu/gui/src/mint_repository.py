from typing import Dict

from cashu.gui.src.models.gui_mint import GuiMint


MintDict = Dict[str, GuiMint]
MintList = list[GuiMint]


class MintRepository:
    _instance = None
    _mints: MintDict = {
        "local1": GuiMint("local1", "http://localhost:3338"),
        "local2": GuiMint("local2", "http://localhost:3339"),
    }

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls._instance, cls):
            cls._instance = super(MintRepository, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    @property
    def mints(self) -> MintDict:
        return self._mints

    @property
    def mint_list(self) -> MintList:
        return list(self._mints.values())

    @property
    def default_mint(self) -> GuiMint:
        return list(self._mints.values())[0]

    def get_mint_per_name(self, name: str):
        return self._mints[name]

    def get_mint_per_url(self, url: str):
        for m in self._mints.values():
            if m.url == url:
                return m

        raise KeyError(f"Could not find mint with url {url}")
