"""Exact-match SHA-256 blocklist engine.

Hash list format (``*.hashes``): one entry per line, ``<sha256> [name]``.
Blank lines and lines starting with ``#`` are ignored.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from venom.engines.base import Engine, ScanObject, classify_signature
from venom.models import Detection, EngineInfo

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class HashListError(ValueError):
    pass


def parse_hash_list(text: str, origin: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, name = re.sub(r"\s+", " ", line).partition(" ")
        if not _HEX64.match(digest):
            raise HashListError(f"{origin}:{lineno}: expected a SHA-256 hex digest")
        entries[digest.lower()] = name.strip() or f"Hash.Blocklisted.{digest[:12].lower()}"
    return entries


class HashEngine(Engine):
    name = "hash"

    def __init__(self, sources: Iterable[tuple[str, str]] = ()) -> None:
        self._db: dict[str, tuple[str, str]] = {}
        for origin, text in sources:
            self.add(origin, text)

    def add(self, origin: str, text: str) -> int:
        entries = parse_hash_list(text, origin)
        for digest, name in entries.items():
            self._db[digest] = (name, origin)
        return len(entries)

    @classmethod
    def from_files(cls, paths: Iterable[Path]) -> HashEngine:
        engine = cls()
        for path in paths:
            engine.add(str(path), path.read_text(encoding="utf-8"))
        return engine

    def __len__(self) -> int:
        return len(self._db)

    def info(self) -> EngineInfo:
        return EngineInfo(self.name, True, detail=f"{len(self._db)} hashes")

    def scan(self, obj: ScanObject) -> list[Detection]:
        hit = self._db.get(obj.sha256)
        if hit is None:
            return []
        name, origin = hit
        severity, category = classify_signature(name)
        return [Detection(self.name, name, severity, category, "SHA-256 blocklist match", origin)]
