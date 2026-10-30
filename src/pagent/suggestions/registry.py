"""Suggestion Source Registry.

Loads small, curated "what to consider / where to look" metadata files per weakness category and
hands the relevant one to the model as guidance. This is deliberately NOT a payload database:
each file may carry at most a couple of harmless example patterns, enough to prove the
infrastructure works. Real payload curation is a later milestone.

Stored as JSON (config/, like every other config file in this project) rather than YAML, since
the project has no YAML dependency or convention anywhere else and this doesn't need one either.
"""
from __future__ import annotations

import json
import os

REQUIRED_KEYS = {"category", "description", "consider", "references", "example_patterns"}
MAX_EXAMPLE_PATTERNS = 3          # enforced on load: this registry must never grow into a payload library
MAX_FIELD_ITEMS = 20


class SuggestionSourceError(ValueError):
    pass


class SuggestionSourceRegistry:
    """Loads suggestion-source files from a directory on construction (fail fast on a malformed
    file) and serves them up by category. Never treats a loaded file as evidence, and never
    authorizes anything - it is pure guidance text handed to the model alongside real context."""

    def __init__(self, directory: str):
        self.directory = directory
        self._sources: dict = {}
        self._load_all()

    def _load_all(self) -> None:
        if not os.path.isdir(self.directory):
            return
        for name in sorted(os.listdir(self.directory)):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self.directory, name)
            with open(path, encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    raise SuggestionSourceError(f"{name}: not valid JSON") from e
            source = self._validate(name, data)
            self._sources[source["category"]] = source

    @staticmethod
    def _validate(name: str, data) -> dict:
        if not isinstance(data, dict):
            raise SuggestionSourceError(f"{name}: must be a JSON object")
        missing = REQUIRED_KEYS - set(data)
        if missing:
            raise SuggestionSourceError(f"{name}: missing key(s) {sorted(missing)}")
        extra = set(data) - REQUIRED_KEYS
        if extra:
            raise SuggestionSourceError(f"{name}: unexpected key(s) {sorted(extra)}")
        if not isinstance(data["category"], str) or not data["category"]:
            raise SuggestionSourceError(f"{name}: 'category' must be a non-empty string")
        if not isinstance(data["description"], str) or not data["description"]:
            raise SuggestionSourceError(f"{name}: 'description' must be a non-empty string")
        for key in ("consider", "references", "example_patterns"):
            v = data[key]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise SuggestionSourceError(f"{name}: '{key}' must be a list of strings")
            if len(v) > MAX_FIELD_ITEMS:
                raise SuggestionSourceError(f"{name}: '{key}' has too many entries")
        if len(data["example_patterns"]) > MAX_EXAMPLE_PATTERNS:
            raise SuggestionSourceError(
                f"{name}: example_patterns must stay minimal (<= {MAX_EXAMPLE_PATTERNS}); "
                "this registry is strategy guidance, not a payload library")
        return data

    def categories(self) -> list:
        return sorted(self._sources)

    def get(self, category: str) -> dict | None:
        """Returns the guidance dict for a category, or None for an unknown category - callers
        should treat an unknown category as "no extra guidance available", not an error."""
        return self._sources.get(category)

    def guidance_for(self, weakness_type: str) -> dict:
        """What to actually hand the model: the category metadata if we have it, otherwise an
        explicit empty-guidance marker so the prompt is honest about not having anything curated
        for this category yet, rather than silently omitting the field."""
        source = self.get(weakness_type)
        if source is None:
            return {"category": weakness_type, "available": False}
        return {
            "category": source["category"],
            "available": True,
            "description": source["description"],
            "consider": source["consider"],
            "references": source["references"],
            "example_patterns": source["example_patterns"],
        }
