from collections import UserList
from .event import Event


class Filter:
    def __init__(
        self,
        ids: "list[str]" = None,
        kinds: "list[int]" = None,
        authors: "list[str]" = None,
        since: int = None,
        until: int = None,
        tags: "dict[str, list[str]]" = None,
        limit: int = None,
    ) -> None:
        self.IDs = ids
        self.kinds = kinds
        self.authors = authors
        self.since = since
        self.until = until
        self.tags = tags
        self.limit = limit

    def matches(self, event: Event) -> bool:
        if self.IDs != None and event.id not in self.IDs:
            return False
        if self.kinds != None and event.kind not in self.kinds:
            return False
        if self.authors != None and event.public_key not in self.authors:
            return False
        if self.since != None and event.created_at < self.since:
            return False
        if self.until != None and event.created_at > self.until:
            return False
        if self.tags != None and len(event.tags) == 0:
            return False
        if self.tags != None:
            e_tag_identifiers = [e_tag[0] for e_tag in event.tags]
            for f_tag, f_tag_values in self.tags.items():
                if f_tag[1:] not in e_tag_identifiers:
                    return False
                for e_tag in event.tags:
                    if e_tag[1] not in f_tag_values:
                        return False

        return True

    def to_json_object(self) -> dict:
        res = {}
        if self.IDs != None:
            res["ids"] = self.IDs
        if self.kinds != None:
            res["kinds"] = self.kinds
        if self.authors != None:
            res["authors"] = self.authors
        if self.since != None:
            res["since"] = self.since
        if self.until != None:
            res["until"] = self.until
        if self.tags != None:
            for tag, values in self.tags.items():
                res[tag] = values
        if self.limit != None:
            res["limit"] = self.limit

        return res


class Filters(UserList):
    def __init__(self, initlist: "list[Filter]" = []) -> None:
        super().__init__(initlist)
        self.data: "list[Filter]"

    def match(self, event: Event):
        for filter in self.data:
            if filter.matches(event):
                return True
        return False

    def to_json_array(self) -> list:
        return [filter.to_json_object() for filter in self.data]
