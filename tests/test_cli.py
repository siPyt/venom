from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import TEST_RULE, zip_bytes
from venom import __version__
from venom.cli import main


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def write_config(home: Path, text: str) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def offline(home: Path) -> Path:
    """No rule feeds and no ClamAV, so CLI runs are hermetic."""
    return write_config(home, "feeds = []\n[clamav]\nmode = 'off'\n")


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert f"venom {__version__}" in capsys.readouterr().out


def test_no_command_is_usage_error(capsys: pytest.CaptureFixture[str], offline: Path) -> None:
    assert run(capsys)[0] == 2


def test_scan_exit_codes(
    capsys: pytest.CaptureFixture[str], offline: Path, samples: Path, marker: bytes
) -> None:
    (samples / "good.txt").write_bytes(b"fine")
    code, out, _ = run(capsys, "scan", str(samples))
    assert code == 0, out
    assert "Result: no threats found" in out

    (samples / "bad.txt").write_bytes(marker)
    code, out, _ = run(capsys, "scan", str(samples))
    assert code == 1
    assert "THREATS FOUND (1)" in out and TEST_RULE in out

    code, out, _ = run(capsys, "scan", str(samples / "missing"))
    assert code == 3
    assert "NOT FULLY SCANNED" in out and "not_found" in out


def test_scan_json_and_report_file(
    capsys: pytest.CaptureFixture[str],
    offline: Path,
    samples: Path,
    marker: bytes,
    tmp_path: Path,
) -> None:
    (samples / "a.zip").write_bytes(zip_bytes({"x/payload.txt": marker}))
    report_path = tmp_path / "report.json"
    code, out, _ = run(capsys, "scan", str(samples), "--json", "--report", str(report_path))
    assert code == 1
    data = json.loads(out)
    assert data == json.loads(report_path.read_text(encoding="utf-8"))
    (finding,) = data["findings"]
    assert finding["member"] == ["x/payload.txt"]
    assert finding["detections"][0]["name"] == TEST_RULE


def test_scan_options(
    capsys: pytest.CaptureFixture[str], offline: Path, samples: Path, marker: bytes
) -> None:
    (samples / "bad.txt").write_bytes(marker)
    assert run(capsys, "scan", str(samples), "--exclude", "*.txt")[0] == 0
    assert run(capsys, "scan", str(samples), "--max-file-size", "4")[0] == 3
    (samples / "bad.txt").unlink()
    (samples / "a.zip").write_bytes(zip_bytes({"payload.txt": marker}))
    assert run(capsys, "scan", str(samples), "--no-archives", "-q")[0] == 0
    assert run(capsys, "scan", str(samples), "--max-file-size", "lots")[0] == 4


def test_scan_quarantine_restore_delete(
    capsys: pytest.CaptureFixture[str], offline: Path, samples: Path, marker: bytes
) -> None:
    bad = samples / "bad.txt"
    bad.write_bytes(marker)
    code, out, _ = run(capsys, "scan", str(samples), "--quarantine", "--yes")
    assert code == 1
    assert "Quarantined" in out
    assert not bad.exists()

    code, out, _ = run(capsys, "quarantine", "list", "--json")
    (entry,) = json.loads(out)
    assert entry["original_path"] == str(bad)
    assert "key" not in entry

    assert run(capsys, "quarantine", "restore", entry["id"][:20])[0] == 0
    assert bad.read_bytes() == marker
    code, out, _ = run(capsys, "quarantine", "list")
    assert "Quarantine is empty" in out

    run(capsys, "scan", str(samples), "--quarantine", "--yes")
    (entry,) = json.loads(run(capsys, "quarantine", "list", "--json")[1])
    code, _, err = run(capsys, "quarantine", "delete", entry["id"])
    assert code == 2 and "--yes" in err
    assert run(capsys, "quarantine", "delete", entry["id"], "--yes")[0] == 0
    assert json.loads(run(capsys, "quarantine", "list", "--json")[1]) == []
    assert run(capsys, "quarantine", "restore", entry["id"])[0] == 4


def test_quarantine_needs_confirmation_when_not_interactive(
    capsys: pytest.CaptureFixture[str], offline: Path, samples: Path, marker: bytes
) -> None:
    bad = samples / "bad.txt"
    bad.write_bytes(marker)
    code, _, err = run(capsys, "scan", str(samples), "--quarantine")
    assert code == 1
    assert "confirmation is required" in err
    assert bad.exists()

    code, _, err = run(capsys, "scan", str(samples), "--quarantine", "--json")
    assert code == 2 and "requires --yes" in err
    assert bad.exists()


def test_invalid_config_exit_code(capsys: pytest.CaptureFixture[str], home: Path) -> None:
    write_config(home, "nonsense = 1\n")
    code, _, err = run(capsys, "status")
    assert code == 4 and "configuration error" in err


def test_config_commands(capsys: pytest.CaptureFixture[str], home: Path) -> None:
    code, out, _ = run(capsys, "config", "path")
    assert code == 0 and out.strip().endswith("config.toml")
    assert run(capsys, "config", "init")[0] == 0
    assert (home / "config.toml").is_file()
    assert run(capsys, "config", "init")[0] == 4
    assert run(capsys, "config", "init", "--force")[0] == 0
    code, out, _ = run(capsys, "config", "show")
    assert code == 0 and json.loads(out)["limits"]["max_archive_depth"] == 3


def test_rules_check(capsys: pytest.CaptureFixture[str], offline: Path, tmp_path: Path) -> None:
    good = tmp_path / "good.yar"
    good.write_text('rule Good { strings: $a = "x" condition: $a }', encoding="utf-8")
    bad = tmp_path / "bad.yar"
    bad.write_text("rule Bad { condition: nope }", encoding="utf-8")
    hashes = tmp_path / "list.hashes"
    hashes.write_text(f"{'a' * 64} Name\n", encoding="utf-8")

    assert run(capsys, "rules", "check", str(good), str(hashes))[0] == 0
    code, out, _ = run(capsys, "rules", "check", str(good), str(bad))
    assert code == 4 and "ERROR" in out
    code, out, _ = run(capsys, "rules", "check")
    assert code == 0 and "No rule files" in out
    assert run(capsys, "rules", "check", str(tmp_path / "missing.yar"))[0] == 4


def test_update_status_and_rollback(
    capsys: pytest.CaptureFixture[str], home: Path, tmp_path: Path, samples: Path
) -> None:
    bundle = tmp_path / "rules.zip"
    rule = 'rule Cli_Feed_Rule { meta: score = 90 strings: $a = "cli-feed-token" condition: $a }'
    bundle.write_bytes(zip_bytes({"a.yar": rule.encode()}))
    write_config(
        home,
        f"[clamav]\nmode = 'off'\n[[feeds]]\nname = 'local'\nurl = '{bundle}'\n",
    )

    code, out, _ = run(capsys, "update", "--no-clamav")
    assert code == 0, out
    assert "updated" in out and "Compiled" in out

    code, out, _ = run(capsys, "status", "--json")
    (feed,) = json.loads(out)["feeds"]
    assert feed["installed"] and feed["rule_count"] == 1 and feed["trust"] == "local file"

    code, out, _ = run(capsys, "status")
    assert code == 0 and "local" in out

    (samples / "x.txt").write_bytes(b"cli-feed-token")
    code, out, _ = run(capsys, "scan", str(samples))
    assert code == 1 and "Cli_Feed_Rule" in out

    assert run(capsys, "update", "--no-clamav")[0] == 0
    assert run(capsys, "update", "--rollback", "local")[0] == 4
    assert run(capsys, "update", "--feed", "nope", "--no-clamav")[0] == 2


def test_bundle_commands(capsys: pytest.CaptureFixture[str], offline: Path, tmp_path: Path) -> None:
    keys = tmp_path / "keys"
    code, out, _ = run(capsys, "bundle", "keygen", "--out", str(keys))
    assert code == 0 and "public_key" in out
    assert run(capsys, "bundle", "keygen", "--out", str(keys))[0] == 4

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yar").write_text('rule R { strings: $a = "r" condition: $a }', encoding="utf-8")
    out_zip = tmp_path / "dist" / "venom-rules.zip"
    code, _, _ = run(
        capsys,
        "bundle",
        "create",
        str(rules),
        "--version",
        "1",
        "--key",
        str(keys / "venom-signing.key"),
        "--out",
        str(out_zip),
    )
    assert code == 0
    assert out_zip.is_file() and out_zip.with_name("venom-rules.zip.sig").is_file()


def test_selftest(capsys: pytest.CaptureFixture[str], offline: Path) -> None:
    code, out, _ = run(capsys, "selftest")
    assert code == 0, out
    assert "Self-test passed" in out
