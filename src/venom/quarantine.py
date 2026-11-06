"""Quarantine: neutralized, integrity-checked storage of detected files.

Quarantined content is XOR-encoded with a random per-item key so it cannot be executed or
re-detected by other scanners in place. This is neutralization, not secrecy. Every restore is
verified against the SHA-256 recorded at quarantine time.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from venom import __version__
from venom.fsutil import NotRegularFile, open_regular
from venom.models import Detection

MAGIC = b"VENOMQ1\0"
_KEY_SIZE = 32
_CHUNK = 1024 * 1024
_ID_RE = re.compile(r"^[0-9A-Za-z-]{1,64}$")


class QuarantineError(Exception):
    pass


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    sha256: str
    size: int
    quarantined_at: str
    key: str
    mode: int | None = None
    detections: list[dict[str, Any]] = field(default_factory=list)
    venom_version: str = __version__
    platform: str = sys.platform

    @property
    def summary(self) -> str:
        names = sorted({d.get("name", "?") for d in self.detections})
        return ", ".join(names) or "(no detection recorded)"

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("key")
        return data


def _xor(chunk: bytes, key: bytes, offset: int) -> bytes:
    """XOR ``chunk`` with ``key`` repeated, aligned to absolute stream ``offset``."""
    if not chunk:
        return chunk
    start = offset % len(key)
    rotated = key[start:] + key[:start]
    n = len(chunk)
    keystream = (rotated * (n // len(key) + 1))[:n]
    return (int.from_bytes(chunk, "little") ^ int.from_bytes(keystream, "little")).to_bytes(
        n, "little"
    )


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _remove(path: Path) -> None:
    try:
        os.remove(path)
    except PermissionError:
        # Windows refuses to delete read-only files; clear the flag and retry once.
        if os.name != "nt":
            raise
        os.chmod(path, stat.S_IWRITE)
        os.remove(path)


class QuarantineStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.root, 0o700)

    def _files(self, entry_id: str) -> tuple[Path, Path]:
        if not _ID_RE.match(entry_id):
            raise QuarantineError(f"invalid quarantine id: {entry_id!r}")
        return self.root / f"{entry_id}.bin", self.root / f"{entry_id}.json"

    # ------------------------------------------------------------- queries

    def list(self) -> list[QuarantineEntry]:
        if not self.root.is_dir():
            return []
        entries = []
        for meta in self.root.glob("*.json"):
            try:
                entries.append(QuarantineEntry(**json.loads(meta.read_text(encoding="utf-8"))))
            except (OSError, ValueError, TypeError):
                continue
        return sorted(entries, key=lambda e: (e.quarantined_at, e.id))

    def get(self, id_or_prefix: str) -> QuarantineEntry:
        matches = [e for e in self.list() if e.id.startswith(id_or_prefix)]
        if not matches:
            raise QuarantineError(f"no quarantined item matches {id_or_prefix!r}")
        exact = [e for e in matches if e.id == id_or_prefix]
        if exact:
            return exact[0]
        if len(matches) > 1:
            raise QuarantineError(f"{id_or_prefix!r} is ambiguous; use more characters of the id")
        return matches[0]

    # ------------------------------------------------------------- actions

    def add(
        self,
        path: str | os.PathLike[str],
        *,
        expected_sha256: str | None,
        detections: list[Detection],
    ) -> QuarantineEntry:
        """Move ``path`` into quarantine. On any failure the original is left untouched."""
        self._ensure_root()
        source = Path(os.path.abspath(path))
        try:
            fh, before = open_regular(source, follow_symlinks=False)
        except NotRegularFile as exc:
            raise QuarantineError(
                f"{source}: not a regular file (links are never followed)"
            ) from exc
        except OSError as exc:
            raise QuarantineError(f"{source}: cannot open: {exc.strerror or exc}") from exc

        stamp = datetime.now(UTC)
        entry_id = f"{stamp:%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"
        blob, meta = self._files(entry_id)
        part = blob.with_name(blob.name + ".part")
        key = secrets.token_bytes(_KEY_SIZE)
        digest = hashlib.sha256()
        size = 0
        try:
            with fh, open(part, "xb") as out:
                out.write(MAGIC)
                while chunk := fh.read(_CHUNK):
                    digest.update(chunk)
                    out.write(_xor(chunk, key, size))
                    size += len(chunk)
                out.flush()
                os.fsync(out.fileno())
            actual = digest.hexdigest()
            if expected_sha256 and actual != expected_sha256:
                raise QuarantineError(
                    f"{source}: file changed since it was scanned; rescan before quarantining"
                )
            after = os.lstat(source)
            if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
                raise QuarantineError(f"{source}: file changed while being quarantined")
            entry = QuarantineEntry(
                id=entry_id,
                original_path=str(source),
                sha256=actual,
                size=size,
                quarantined_at=stamp.isoformat(timespec="seconds"),
                key=key.hex(),
                mode=stat.S_IMODE(before.st_mode),
                detections=[d.to_dict() for d in detections],
            )
            _write_json_atomic(meta, asdict(entry))
            os.replace(part, blob)
        except BaseException:
            part.unlink(missing_ok=True)
            meta.unlink(missing_ok=True)
            raise

        try:
            _remove(source)
        except OSError as exc:
            self._discard(entry_id)
            raise QuarantineError(
                f"{source}: could not remove the original ({exc.strerror or exc}); "
                "it was left in place and nothing was quarantined"
            ) from exc
        return entry

    def restore(
        self,
        id_or_prefix: str,
        destination: str | os.PathLike[str] | None = None,
        *,
        overwrite: bool = False,
    ) -> Path:
        entry = self.get(id_or_prefix)
        blob, _ = self._files(entry.id)
        target = Path(destination) if destination else Path(entry.original_path)
        if target.is_dir():
            target = target / Path(entry.original_path).name
        if target.exists() and not overwrite:
            raise QuarantineError(
                f"{target} already exists; use --overwrite or choose another location with --to"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.venom-restore-{secrets.token_hex(4)}")
        key = bytes.fromhex(entry.key)
        digest = hashlib.sha256()
        try:
            with open(blob, "rb") as src, open(tmp, "xb") as out:
                if src.read(len(MAGIC)) != MAGIC:
                    raise QuarantineError(f"quarantine item {entry.id} is corrupt (bad header)")
                offset = 0
                while chunk := src.read(_CHUNK):
                    plain = _xor(chunk, key, offset)
                    digest.update(plain)
                    out.write(plain)
                    offset += len(chunk)
                out.flush()
                os.fsync(out.fileno())
            if digest.hexdigest() != entry.sha256:
                raise QuarantineError(
                    f"quarantine item {entry.id} failed its integrity check; nothing was restored"
                )
            if entry.mode is not None and os.name != "nt":
                os.chmod(tmp, entry.mode & 0o777)
            self._place(tmp, target, overwrite)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise QuarantineError(f"cannot restore to {target}: {exc.strerror or exc}") from exc
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        self._discard(entry.id)
        return target

    def delete(self, id_or_prefix: str) -> QuarantineEntry:
        entry = self.get(id_or_prefix)
        self._discard(entry.id)
        return entry

    def _discard(self, entry_id: str) -> None:
        blob, meta = self._files(entry_id)
        blob.unlink(missing_ok=True)
        meta.unlink(missing_ok=True)

    @staticmethod
    def _place(tmp: Path, target: Path, overwrite: bool) -> None:
        if overwrite:
            os.replace(tmp, target)
            return
        try:
            # A hard link fails atomically if the target appeared in the meantime.
            os.link(tmp, target)
        except FileExistsError as exc:
            raise QuarantineError(f"{target} already exists; nothing was restored") from exc
        except OSError:
            if target.exists():
                raise QuarantineError(f"{target} already exists; nothing was restored") from None
            os.rename(tmp, target)
            return
        try:
            tmp.unlink()
        except OSError:
            pass
