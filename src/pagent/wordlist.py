"""Loads and validates the content-discovery wordlist (config/content_discovery_wordlist.json): a
small, checked-in, human-reviewed list of path SEGMENTS to check for existence under an explicitly
scoped prefix (see Scope.discovery_prefixes, pagent.discover.run_content_discovery,
pagent.tools.dir_probe). This is directory/file EXISTENCE checking against common, benign
filenames - not an exploit payload list (see pagent.suggestions.registry for that, separately and
even more tightly capped) and not a general-purpose fuzzing wordlist: MAX_ENTRIES keeps it small
on purpose, and every entry is validated as a single safe path segment before use - no '/' (so an
entry can never smuggle in extra path depth or escape the scoped prefix), no '..' (no traversal),
nothing outside a conservative filename character set.
"""
from __future__ import annotations
import json
import re

MAX_ENTRIES = 60
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


class WordlistError(ValueError):
    pass


def _is_safe_segment(entry: str) -> bool:
    return bool(_SEGMENT_RE.match(entry)) and ".." not in entry and entry not in (".", "..")


def load_wordlist(path: str) -> tuple:
    """Returns a deduplicated tuple of validated path segments, in file order. Raises
    WordlistError (fail closed) for anything malformed, oversized, or unsafe - a bad wordlist
    file should never silently become a smaller, "good enough" one."""
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise WordlistError(f"{path}: not valid JSON") from e
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        raise WordlistError(f"{path}: must be a JSON array of strings")
    if len(data) > MAX_ENTRIES:
        raise WordlistError(f"{path}: {len(data)} entries exceeds the hard cap of {MAX_ENTRIES} - "
                            "this is a small existence-check list, not a general wordlist")
    seen = set()
    out = []
    for entry in data:
        if not _is_safe_segment(entry):
            raise WordlistError(f"{path}: invalid entry {entry!r} - must be one safe path segment "
                                "(no '/', no '..', conservative filename characters only)")
        if entry not in seen:
            seen.add(entry)
            out.append(entry)
    return tuple(out)
