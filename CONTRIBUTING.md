# Contributing to Venom

Thanks for helping. Bug reports, detection rules, and code changes are all welcome.

## Development setup

```bash
git clone https://github.com/siPyt/venom.git
cd venom
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

Python 3.11 or newer is required. Installing ClamAV is optional. Without it, the real ClamAV
integration test is skipped. Set `VENOM_REQUIRE_CLAMAV=1` to make that test mandatory.

## Before opening a pull request

```bash
ruff check src tests
ruff format src tests
pytest
venom selftest
```

CI runs the same checks on Windows, macOS, and Linux with Python 3.11 and 3.14, and runs a real
ClamAV scan on Linux.

## Ground rules

- **Never commit live malware, EICAR, or the Venom test marker as a literal.** Antivirus products,
  including Windows Defender, quarantine files that contain them, and repositories that contain
  them get flagged. In tests, use the `marker` fixture or `venom.selftest.make_test_marker()`,
  which builds the marker at runtime.
- **Treat every scanned byte as hostile.** Never extract to disk, execute, or follow symlinks in
  scanned content, and keep every read bounded by `Limits`.
- **Never skip silently.** Anything Venom cannot fully scan must become an `Issue`, so that the
  scan reports as incomplete with exit code 3.
- **Add tests for new behavior**, especially for malformed and adversarial input.
- Keep dependencies minimal. Each new dependency expands the attack surface of a security tool.

## Contributing detection rules

Venom loads rules from external feeds and the user’s rules directory. Consider contributing
general-purpose YARA rules upstream to [YARA Forge](https://github.com/YARAHQ/yara-forge)
sources, where every Venom user benefits automatically. Rules bundled in `src/venom/data` must
be high confidence, fast, and accompanied by a test that uses harmless synthetic data.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.
