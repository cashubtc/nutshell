from collections import UserList
from typing import List

from .event import Event, EventKind


class Filter:
    """
    NIP-01 filtering.

    Explicitly supports "#e" and "#p" tag filters via `event_refs` and `pubkey_refs`.

    Arbitrary NIP-12 single-letter tag filters are also supported via `add_arbitrary_tag`.
    If a particular single-letter tag gains prominence, explicit support should be
    added. For example:
        # arbitrary tag
        filter.add_arbitrary_tag('t', [hashtags])

        # promoted to explicit support
        Filter(hashtag_refs=[hashtags])
    """

    def __init__(
        self,
        event_ids: List[str] = None,
        kinds: List[EventKind] = None,
        authors: List[str] = None,
        since: int = None,
        until: int = None,
        event_refs: List[
            str
        ] = None,  # the "#e" attr; list of event ids referenced in an "e" tag
        pubkey_refs: List[
            str
        ] = None,  # The "#p" attr; list of pubkeys referenced in a "p" tag
        limit: int = None,
    ) -> None:
        self.event_ids = event_ids
        self.kinds = kinds
        self.authors = authors
        self.since = since
        self.until = until
        self.event_refs = event_refs
        self.pubkey_refs = pubkey_refs
        self.limit = limit

        self.tags = {}
        if self.event_refs:
            self.add_arbitrary_tag("e", self.event_refs)
        if self.pubkey_refs:
            self.add_arbitrary_tag("p", self.pubkey_refs)

    def add_arbitrary_tag(self, tag: str, values: list):
        """
        Filter on any arbitrary tag with explicit handling for NIP-01 and NIP-12
        single-letter tags.
        """
        # NIP-01 'e' and 'p' tags and any NIP-12 single-letter tags must be prefixed with "#"
        tag_key = tag if len(tag) > 1 else f"#{tag}"
        self.tags[tag_key] = values

    def matches(self, event: Event) -> bool:
        if self.event_ids is not None and event.id not in self.event_ids:
            return False
        if self.kinds is not None and event.kind not in self.kinds:
            return False
        if self.authors is not None and event.public_key not in self.authors:
            return False
        if self.since is not None and event.created_at < self.since:
            return False
        if self.until is not None and event.created_at > self.until:
            return False
        if (self.event_refs is not None or self.pubkey_refs is not None) and len(
            event.tags
        ) == 0:
            return False

        if self.tags:
            e_tag_identifiers = set([e_tag[0] for e_tag in event.tags])
            for f_tag, f_tag_values in self.tags.items():
                # Omit any NIP-01 or NIP-12 "#" chars on single-letter tags
                f_tag = f_tag.replace("#", "")

                if f_tag not in e_tag_identifiers:
                    # Event is missing a tag type that we're looking for
                    return False

                # Multiple values within f_tag_values are treated as OR search; an Event
                # needs to match only one.
                # Note: an Event could have multiple entries of the same tag type
                # (e.g. a reply to multiple people) so we have to check all of them.
                match_found = False
                for e_tag in event.tags:
                    if e_tag[0] == f_tag and e_tag[1] in f_tag_values:
                        match_found = True
                        break
                if not match_found:
                    return False

        return True

    def to_json_object(self) -> dict:
        res = {}
        if self.event_ids is not None:
            res["ids"] = self.event_ids
        if self.kinds is not None:
            res["kinds"] = self.kinds
        if self.authors is not None:
            res["authors"] = self.authors
        if self.since is not None:
            res["since"] = self.since
        if self.until is not None:
            res["until"] = self.until
        if self.limit is not None:
            res["limit"] = self.limit
        if self.tags:
            res.update(self.tags)

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
