import datetime
from typing import Optional


class User:
    id: str
    last_access: Optional[datetime.datetime]

    def __init__(self, id: str, last_access: Optional[datetime.datetime] = None):
        self.id = id
        if isinstance(last_access, int):
            last_access = datetime.datetime.fromtimestamp(last_access)
        self.last_access = last_access
