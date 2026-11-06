"""ClamAV integration: clamd (preferred, streamed) or clamscan (batched fallback)."""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterable, Iterator
from pathlib import Path

from venom.config import ClamAVConfig, Limits, MiB
from venom.engines.base import BatchResult, Engine, EngineError, ScanObject, classify_signature
from venom.models import Detection, EngineInfo, Issue, IssueKind

_CHUNK = 256 * 1024
_SOCKET_CANDIDATES = (
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/run/clamd.scan/clamd.sock",
    "/var/run/clamd.scan/clamd.sock",
    "/tmp/clamd.socket",
    "/opt/homebrew/var/run/clamav/clamd.sock",
    "/usr/local/var/run/clamav/clamd.sock",
)
_EXTRA_BIN_DIRS = (
    r"C:\Program Files\ClamAV",
    r"C:\Program Files (x86)\ClamAV",
    r"C:\ClamAV",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
)
NOT_FOUND_NOTICE = (
    "ClamAV was not found, so its malware signature database was not used. Install ClamAV "
    "for much broader coverage: https://docs.clamav.net/manual/Installing.html"
)


def parse_reply(reply: str) -> tuple[str, str | None]:
    """Parse a clamd/clamscan status into ``("ok"|"found"|"error", detail)``."""
    text = reply.strip().rstrip("\0").strip()
    if text.endswith(" FOUND"):
        return "found", text[: -len(" FOUND")].rpartition(": ")[2].strip()
    if text == "OK" or text.endswith(": OK"):
        return "ok", None
    return "error", text


class ClamdClient:
    def __init__(
        self,
        *,
        socket_path: str | None = None,
        host: str = "127.0.0.1",
        port: int = 3310,
        timeout: float = 120.0,
    ) -> None:
        self.socket_path = socket_path
        self.host = host
        self.port = port
        self.timeout = timeout

    @property
    def address(self) -> str:
        return self.socket_path or f"{self.host}:{self.port}"

    def _connect(self, timeout: float | None = None) -> socket.socket:
        timeout = self.timeout if timeout is None else timeout
        if self.socket_path:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect(self.socket_path)
            except BaseException:
                sock.close()
                raise
            return sock
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        sock.settimeout(timeout)
        return sock

    @staticmethod
    def _receive(sock: socket.socket) -> str:
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if chunk.endswith(b"\0"):
                break
        return b"".join(chunks).decode("utf-8", "replace").rstrip("\0").strip()

    def command(self, name: str, timeout: float | None = None) -> str:
        with self._connect(timeout) as sock:
            sock.sendall(b"z" + name.encode("ascii") + b"\0")
            return self._receive(sock)

    def ping(self, timeout: float = 2.0) -> bool:
        try:
            return self.command("PING", timeout) == "PONG"
        except OSError:
            return False

    def version(self) -> str:
        return self.command("VERSION", 10.0)

    def instream(self, chunks: Iterable[bytes]) -> str:
        with self._connect() as sock:
            try:
                sock.sendall(b"zINSTREAM\0")
                for chunk in chunks:
                    if chunk:
                        sock.sendall(struct.pack("!L", len(chunk)) + chunk)
                sock.sendall(struct.pack("!L", 0))
            except OSError as exc:
                # clamd closes the connection early when StreamMaxLength is exceeded;
                # its explanation is still waiting in the receive buffer.
                try:
                    reply = self._receive(sock)
                except OSError:
                    reply = ""
                if reply:
                    return reply
                raise EngineError(f"clamd connection failed: {exc}") from exc
            return self._receive(sock)


def _iter_chunks(obj: ScanObject) -> Iterator[bytes]:
    if obj.data is not None:
        view = memoryview(obj.data)
        for offset in range(0, len(view), _CHUNK):
            yield bytes(view[offset : offset + _CHUNK])
        return
    with open(obj.path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            yield chunk


class ClamdEngine(Engine):
    name = "clamav"
    scans_members = False

    def __init__(self, client: ClamdClient, version: str = "") -> None:
        self.client = client
        self.version = version

    def info(self) -> EngineInfo:
        return EngineInfo(self.name, True, self.version, f"clamd at {self.client.address}")

    def scan(self, obj: ScanObject) -> list[Detection]:
        try:
            reply = self.client.instream(_iter_chunks(obj))
        except OSError as exc:
            raise EngineError(f"clamd scan failed: {exc}") from exc
        status, detail = parse_reply(reply)
        if status == "ok":
            return []
        if status == "found" and detail:
            severity, category = classify_signature(detail)
            return [Detection(self.name, detail, severity, category, "ClamAV signature", "clamd")]
        raise EngineError(f"clamd: {detail or reply or 'empty reply'}")


class ClamscanEngine(Engine):
    name = "clamav"
    scans_members = False
    batch = True

    def __init__(self, executable: str, config: ClamAVConfig, limits: Limits, version: str = ""):
        self.executable = executable
        self.config = config
        self.limits = limits
        self.version = version

    def info(self) -> EngineInfo:
        return EngineInfo(self.name, True, self.version, f"clamscan at {self.executable}")

    def _command(self, file_list: str) -> list[str]:
        cmd = [self.executable, "--no-summary", "--stdout", f"--file-list={file_list}"]
        if self.limits.max_file_size:
            cap_mib = max(1, min(self.limits.max_file_size // MiB, 2000))
            cmd += [f"--max-filesize={cap_mib}M", f"--max-scansize={min(cap_mib * 4, 4000)}M"]
        if self.config.database:
            cmd += ["-d", self.config.database]
        return cmd

    def scan_batch(self, paths: list[Path], cancel: threading.Event) -> BatchResult:
        result = BatchResult()
        if not paths:
            return result
        by_key = {os.path.normcase(os.path.abspath(p)): str(p) for p in paths}
        seen: set[str] = set()
        with tempfile.TemporaryDirectory(prefix="venom-clamscan-") as tmp:
            file_list = os.path.join(tmp, "files.txt")
            with open(file_list, "w", encoding="utf-8", errors="surrogateescape") as fh:
                fh.writelines(f"{p}\n" for p in by_key.values())
            stderr_path = os.path.join(tmp, "stderr.txt")
            with open(stderr_path, "w+b") as stderr:
                try:
                    proc = subprocess.Popen(
                        self._command(file_list),
                        stdout=subprocess.PIPE,
                        stderr=stderr,
                        stdin=subprocess.DEVNULL,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                    )
                except OSError as exc:
                    raise EngineError(f"cannot run clamscan: {exc}") from exc
                assert proc.stdout is not None
                with proc:
                    for line in proc.stdout:
                        if cancel.is_set():
                            proc.terminate()
                            break
                        self._handle_line(line.rstrip("\r\n"), by_key, seen, result)
                    returncode = proc.wait()
                stderr.seek(0)
                errors = stderr.read().decode("utf-8", "replace").strip()

        if cancel.is_set():
            return result
        if returncode not in (0, 1) and not seen:
            tail = errors.splitlines()[-3:] if errors else [f"exit code {returncode}"]
            raise EngineError("clamscan failed: " + " | ".join(tail))
        for key, original in by_key.items():
            if key not in seen:
                result.issues.append(
                    Issue(
                        original,
                        IssueKind.ENGINE_ERROR,
                        "not reported by clamscan",
                        engine=self.name,
                    )
                )
        return result

    def _handle_line(
        self, line: str, by_key: dict[str, str], seen: set[str], result: BatchResult
    ) -> None:
        if not line or line.startswith(("LibClamAV", "WARNING")):
            return
        path_part, sep, status = line.rpartition(": ")
        if not sep:
            return
        key = os.path.normcase(os.path.abspath(path_part))
        original = by_key.get(key)
        if original is None:
            return
        seen.add(key)
        kind, detail = parse_reply(line)
        if kind == "found" and detail:
            severity, category = classify_signature(detail)
            result.detections.setdefault(original, []).append(
                Detection(self.name, detail, severity, category, "ClamAV signature", "clamscan")
            )
        elif kind == "error" and status.strip() not in ("Empty file", "Symbolic link"):
            result.issues.append(
                Issue(
                    original,
                    IssueKind.ENGINE_ERROR,
                    f"clamscan: {status.strip()}",
                    engine=self.name,
                )
            )


def find_executable(name: str, configured: str | None = None) -> str | None:
    if configured:
        return configured if Path(configured).is_file() else None
    found = shutil.which(name)
    if found:
        return found
    suffix = ".exe" if sys.platform == "win32" else ""
    for directory in _EXTRA_BIN_DIRS:
        candidate = Path(directory) / f"{name}{suffix}"
        if candidate.is_file():
            return str(candidate)
    return None


def _executable_version(executable: str) -> str:
    try:
        out = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip().splitlines()[0] if out.stdout.strip() else ""


def _find_clamd(config: ClamAVConfig) -> ClamdClient | None:
    candidates: list[ClamdClient] = []
    if hasattr(socket, "AF_UNIX"):
        sockets = [config.clamd_socket] if config.clamd_socket else list(_SOCKET_CANDIDATES)
        for path in sockets:
            if path and os.path.exists(path):
                candidates.append(ClamdClient(socket_path=path, timeout=config.clamd_timeout))
    candidates.append(
        ClamdClient(host=config.clamd_host, port=config.clamd_port, timeout=config.clamd_timeout)
    )
    for client in candidates:
        if client.ping(timeout=1.0):
            return client
    return None


def discover(config: ClamAVConfig, limits: Limits) -> tuple[Engine | None, EngineInfo, list[str]]:
    if config.mode == "off":
        return None, EngineInfo("clamav", False, detail="disabled in configuration"), []
    if config.mode in ("auto", "clamd"):
        client = _find_clamd(config)
        if client is not None:
            try:
                version = client.version()
            except OSError:
                version = ""
            engine = ClamdEngine(client, version)
            return engine, engine.info(), []
        if config.mode == "clamd":
            message = "clamd is not reachable; ClamAV scanning is disabled for this run."
            return None, EngineInfo("clamav", False, detail="clamd not reachable"), [message]
    executable = find_executable("clamscan", config.clamscan)
    if executable:
        engine = ClamscanEngine(executable, config, limits, _executable_version(executable))
        return engine, engine.info(), []
    return None, EngineInfo("clamav", False, detail="not installed"), [NOT_FOUND_NOTICE]
