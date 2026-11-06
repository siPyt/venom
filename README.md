# Venom

[![CI](https://github.com/siPyt/venom/actions/workflows/ci.yml/badge.svg)](https://github.com/siPyt/venom/actions/workflows/ci.yml)

**Venom is an open-source, cross-platform malware scanner.** It combines
[YARA-X](https://virustotal.github.io/yara-x/) rules, curated community rule feeds,
SHA-256 blocklists, and—when installed—[ClamAV](https://www.clamav.net/)’s malware signature
database behind one consistent scanner, report format, and quarantine.

It runs on **Windows, macOS, and Linux** with Python 3.11+.

> **Status: alpha (0.1).** Venom performs on-demand scanning. Real-time protection is on the
> [roadmap](#roadmap). Use Venom alongside your operating system’s built-in protection (for
> example, Microsoft Defender), not instead of it.

## What it does

| Area | Behavior |
|------|----------|
| **Detection** | YARA-X rules (built-in + feeds + your own), exact SHA-256 blocklists, and ClamAV via `clamd` (streamed) or `clamscan` (batched). |
| **Rule feeds** | Installs [YARA Forge](https://github.com/YARAHQ/yara-forge) “core” by default: ~5,000 quality-filtered community rules. |
| **Archives** | Inspects zip (including Office documents, JARs, and APKs), tar, gzip, bzip2, and xz in memory, with depth, member-count, size, total-byte, and compression-ratio limits. Never extracts to disk. |
| **Honest results** | Anything not fully scanned—unreadable, too large, encrypted, over an archive limit, or timed out—is listed explicitly and sets exit code `3`. A clean result means “clean *and* complete.” |
| **Safe remediation** | Nothing is changed unless you ask. Quarantine neutralizes the file, verifies it hasn’t changed since the scan, and only then removes the original; restores are verified against the original SHA-256. |
| **Trustworthy updates** | HTTPS-only downloads, including redirects; optional SHA-256 pinning; Ed25519-signed bundles with rollback protection; validation before activation; atomic swaps; and `--rollback`. |
| **Safe traversal** | Doesn’t follow symlinks or Windows junctions by default, refuses FIFOs and devices, and skips cloud-only OneDrive/iCloud placeholders so a scan doesn’t download your cloud drive. |
| **Privacy** | Scanning is fully local. Venom never uploads files or hashes anywhere. |

## Install

```bash
git clone https://github.com/siPyt/venom.git
cd venom
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install .
```

**Strongly recommended:** install ClamAV for its multi-million-signature database. Venom
detects and uses it automatically.

| Platform | Command |
|----------|---------|
| Debian/Ubuntu | `sudo apt install clamav clamav-daemon` |
| Fedora/RHEL | `sudo dnf install clamav clamav-update clamd` |
| macOS (Homebrew) | `brew install clamav` (then create `freshclam.conf` from the sample) |
| Windows | Installer from [clamav.net/downloads](https://www.clamav.net/downloads) |

If the `clamd` daemon is running, Venom streams files to it (fast). Otherwise it runs
`clamscan` once per scan with a file list, which is slower because ClamAV loads its database on each run.

## Quick start

```bash
venom update            # download rule feeds and run freshclam (if ClamAV is installed)
venom selftest          # verify detection, archive scanning and quarantine end to end
venom scan ~/Downloads  # scan; nothing is modified
venom scan ~/Downloads --quarantine     # scan, then confirm quarantine for each detection
venom status            # engines, rule versions and ages, quarantine count
```

### Scanning

```text
venom scan PATH... [--json] [--report FILE] [--quarantine [--yes]]
                   [--exclude GLOB] [--max-file-size SIZE] [--workers N]
                   [--no-archives] [--no-clamav] [--follow-symlinks]
                   [--include-offline] [-v] [-q]
```

| Exit code | Meaning |
|-----------|---------|
| `0` | No threats, and everything was fully scanned |
| `1` | Threats found |
| `2` | Usage error |
| `3` | No threats found, but some items could not be fully scanned (listed in the report) |
| `4` | Error, such as invalid configuration or a failed update |
| `130` | Cancelled with Ctrl+C; partial results are still reported |

`--json` / `--report FILE` emit a stable, versioned JSON report (`"schema": 1`) for automation.

### Quarantine

```bash
venom quarantine list
venom quarantine restore <id> [--to PATH] [--overwrite]
venom quarantine delete <id>
```

A file inside an archive can’t be removed on its own, so Venom quarantines the containing archive
and says so in the prompt.

### Custom rules

Put `*.yar`, `*.yara`, or `*.hashes` files in your rules directory (`venom status` shows where).
Each user rule file is compiled in its own namespace. A broken file is skipped with a notice
instead of disabling every other rule. To validate them:

```bash
venom rules check            # checks your rules directory
venom rules check my.yar     # checks specific files
```

Hash lists contain one entry per line: `<sha256> [Name]`. Names beginning with `PUA.` are
reported as potentially unwanted (low severity).

## Configuration

`venom config init` writes a commented `config.toml`; `venom config path` shows where. All
settings are optional, and unknown keys are rejected so typos don’t go unnoticed. Set
`VENOM_HOME=/some/dir` to keep configuration and data in one portable directory. Venom’s own data
and rules directories are always skipped during scans, because signature files would otherwise
match themselves.

```toml
exclude = ["*/node_modules", "*.iso"]

[limits]
max_file_size = "512M"

[clamav]
mode = "clamd"          # auto | clamd | clamscan | off
clamd_socket = "/run/clamav/clamd.ctl"

[[feeds]]               # defining feeds replaces the defaults
name = "yara-forge-extended"
url = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip"
```

## Update security

| Feed type | Authentication |
|-----------|----------------|
| Default (YARA Forge) | HTTPS with certificate validation; redirects to non-HTTPS URLs are refused |
| `sha256 = "..."` | Exact pinned digest |
| `public_key = "..."` | Ed25519 signature over the bundle digest, plus a monotonic manifest version that blocks downgrade attacks |

Every update is size-capped, extracts only rule files under names Venom generates itself, and
must compile before activation. The previous version is kept for `venom update --rollback NAME`.
If any step fails, the active rules are left untouched.

### Publishing signed rule bundles

```bash
venom bundle keygen --out ./keys        # keep keys/venom-signing.key secret
venom bundle create ./my-rules --version 1 --key ./keys/venom-signing.key --out venom-rules.zip
# Publish venom-rules.zip and venom-rules.zip.sig; clients configure the printed public key.
```

Set `VENOM_KEY_PASSPHRASE` to encrypt the private key at generation time and to unlock it when
signing.

## Testing detection

Real antivirus products, including Microsoft Defender, delete the EICAR test file on sight, so
Venom also ships a harmless test signature of its own. `venom selftest` writes it to a temporary
directory, both as a plain file and inside a zip, and checks detection, quarantine, and verified
restore. Venom also detects the EICAR test file by hash.

## Roadmap

1. **On-demand scanning, findings, quarantine, and updates** ← *v0.1, this release*
2. Desktop interface, scheduled scans, and HTML reports
3. Real-time protection: fanotify on Linux, Endpoint Security on macOS, and a minifilter or ETW on
   Windows
4. Optional modules for auditing systems and networks you are authorized to assess (for example,
   Nmap and TShark integrations)
5. A multi-process YARA backend for CPU-parallel scanning

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
ruff format --check src tests
pytest
```

Continuous integration runs on Windows, macOS, and Linux. On Linux it also runs a real ClamAV
integration test. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Rule feeds you download keep their own licenses. ClamAV is a
separate GPL-2.0 program that Venom runs as an external process.
