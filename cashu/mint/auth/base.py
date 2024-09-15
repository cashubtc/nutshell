class User:
    id: str
    quota: int

    def __init__(self, id: str):
        self.id = id
        self.quota = 0
