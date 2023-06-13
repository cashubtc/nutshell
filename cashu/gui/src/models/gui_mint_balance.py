class GuiMintBalance:
    mint_name: str
    balance: float
    available: float
    percent: float

    def __init__(
        self, mint_name: str, balance: float, available: float, percent: float
    ):
        self.mint_name = mint_name
        self.balance = balance
        self.available = available
        self.percent = percent
