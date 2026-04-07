# AI Supply Chain Security

Cross-platform supply chain security scanner for **Claude Code** and **OpenClaw**. Detects hardcoded secrets, malicious dependencies, lock file poisoning, registry hijacking, IDE configuration attacks, build script exploits, and AI prompt injection — **zero configuration required**.

## Skill Information

```yaml
name: ai-supply-chain-security
version: 2.2.0
description: >
  Install-and-run supply chain security scanner for AI coding environments.
  Automatically detects 60+ threat patterns across npm/PyPI/Rust ecosystems,
  GitHub Actions, IDE configs, build scripts, and AI assistant configurations.
author: JavaMaGong
platforms: [Windows, macOS, Linux]
category: security
python: ">=3.8"
```

## Quick Start

### OpenClaw
```bash
openclaw skills install ai-supply-chain-security
/security-scan                         # scan current project
/security-scan /path/to/project        # scan specific path
```

### Claude Code (Manual)
```bash
git clone https://github.com/javamagong/ai-supply-chain-security.git
python ai-scanner.py                   # scan current directory
python ai-scanner.py -d /your/project  # scan specific path
```

### CI/CD
```bash
python ai-scanner.py -d . --ci -f json -o security-report.json
# exit 0 = clean, exit 1 = warnings, exit 2 = critical findings
```

---

## What Gets Detected

### 1. Hardcoded API Key / Credential Exposure

Scans all source files (`.py`, `.js`, `.ts`, `.go`, `.rs`, `.env`, `.yaml`, etc.) for real credentials:

| Rule | Provider | Severity |
|------|----------|----------|
| SECRET-001 | Anthropic API Key (`sk-ant-`) | CRITICAL |
| SECRET-002 | OpenAI API Key (`sk-proj-` / `sk-`) | CRITICAL |
| SECRET-003 | AWS Access Key ID (`AKIA...`) | CRITICAL |
| SECRET-004 | GitHub PAT classic (`ghp_`) | CRITICAL |
| SECRET-005 | GitHub Fine-grained PAT (`github_pat_`) | CRITICAL |
| SECRET-006 | Slack Token (`xoxb-`) | CRITICAL |
| SECRET-007 | Google API Key (`AIza`) | CRITICAL |
| SECRET-008 | HuggingFace Token (`hf_`) | WARNING |

**False-positive prevention**: skips test files, `.example`/`.sample` files, placeholder patterns, and `node_modules/`. Matched values are redacted in output (shows prefix...suffix only).

---

### 2. Supply Chain Attack Detection

**npm / Node.js:**
- 24 known malicious packages (event-stream, flatmap-stream, colors, node-ipc, ua-parser-js, etc.)
- 150+ typosquatting variants (opeanai, litelm, axois, reqeusts, etc.)
- Dangerous lifecycle scripts (`postinstall`, `preinstall`, `prepare`, `install`) with curl/wget/bash
- Unicode homoglyph package names (Cyrillic/Greek lookalike characters)

**Python / PyPI:**
- Malicious `setup.py` patterns (exec, eval, subprocess, network requests)
- Suspicious `pyproject.toml` entry points and build backends
- Git URL dependencies, unofficial index URLs
- Typosquatting + homoglyph detection

**Rust / Cargo:**
- Unpinned versions, git dependencies in `Cargo.toml`

---

### 3. Lock File Poisoning Detection

| Lock File | What's Checked |
|-----------|---------------|
| `package-lock.json` (v1/v2/v3) | Non-official `resolved` URLs, missing `integrity` hashes, known malicious packages |
| `yarn.lock` | Non-yarnpkg.com resolved URLs, missing integrity hashes |
| `poetry.lock` | Git-sourced dependencies, non-PyPI source URLs |
| `Cargo.lock` | `git+` source dependencies, non-crates.io registries, missing checksums |

---

### 4. Registry Substitution Attack Detection

| Config File | What's Checked |
|-------------|---------------|
| `.npmrc` (project + `~/.npmrc`) | Global registry override, scoped registry hijack, hardcoded `_authToken`, `always-auth=true` |
| `pip.conf` / `pip.ini` (project + global) | Non-official `index-url`, `extra-index-url` (dependency confusion), `trusted-host` TLS bypass |

---

### 5. AI Assistant Configuration Protection

**Claude Code / Cursor:**
- Hooks exfiltrating data via curl/wget/nc to external URLs
- Environment variable theft (`$ANTHROPIC_API_KEY`, `$OPENAI_API_KEY`, `$AWS_*`, etc.)
- Dangerous MCP server URLs (external, non-official)
- Destructive hook commands (`rm -rf`, `curl | bash`, `base64 -d | bash`)

**CLAUDE.md / `.cursorrules` Prompt Injection:**
- 7 injection pattern families (role redefinition, instruction override, system prompt extraction, etc.)
- Hidden Unicode characters (zero-width spaces U+200B, UFEFF, U+200C, etc.)
- Base64-encoded hidden instructions

---

### 6. Rust Build Script (`build.rs`) Compile-time RCE

Rust `build.rs` runs at `cargo build` time with full host access. Detects:
- Shell/network tools spawned at compile time (`Command::new("curl")`, `Command::new("bash")`)
- TCP/UDP socket connections (`TcpStream::connect`, `UdpSocket::bind`)
- File deletion (`fs::remove_dir_all`, `fs::remove_file`)
- HTTP client library imports (`reqwest`, `ureq`, `hyper`, `isahc`)
- Reading sensitive environment variables at compile time
- Double-risk escalation when `proc-macro = true` co-exists with `build.rs`

---

### 7. IDE Configuration Attacks

**VS Code (`.vscode/`):**
- `tasks.json`: auto-run on folder open (`runOn: folderOpen`) — triggers without user action
- `tasks.json`: tasks executing curl/wget/bash/python/nc
- `settings.json`: `terminal.integrated.env.*` PATH hijacking
- `settings.json`: Python venv auto-activation (malicious activate scripts)

**IntelliJ IDEA (`.idea/`):**
- `workspace.xml`: dangerous run configurations referencing network/shell tools

---

### 8. Makefile / Taskfile Build Script Attacks

| Rule | Pattern | Severity |
|------|---------|----------|
| BUILD-001 | `curl URL \| bash` / `wget URL \| sh` | CRITICAL |
| BUILD-002 | `$(shell curl ...)` / `$(eval wget ...)` | CRITICAL |
| BUILD-003 | Unpinned `pip install` / `npm install -g` in recipes | WARNING |

Covers `Makefile`, `GNUmakefile`, `Taskfile.yml`, `Taskfile.yaml`.

---

### 9. GitHub Actions Supply Chain

| Rule | Pattern | Severity |
|------|---------|----------|
| SUPPLY-020 | Unpinned action (`@main`, `@master`, `@HEAD`) | CRITICAL |
| GHAS-001 | `::set-env` deprecated command injection | CRITICAL |
| GHAS-001 | Pwn Request: `pull_request_target` + fork head checkout | CRITICAL |
| GHAS-002 | Untrusted `github.event.pull_request.title/body` in `run:` | CRITICAL |
| GHAS-003 | `::add-path` deprecated PATH injection | WARNING |
| SUPPLY-021 | Short SHA reference (7 chars) | INFO |

---

### 10. Code Obfuscation Detection

- Large hex-encoded strings (`\x41\x42...` 4+ chars)
- `exec(base64.b64decode(...))` / `eval(bytes.fromhex(...))`
- Dynamic `__import__('os')` / `__import__('subprocess')`
- `chr()`-based string construction
- `exec(compile(...))`

---

## CLI Reference

```bash
python ai-scanner.py                          # Scan current directory
python ai-scanner.py -d /path/to/project      # Scan specific path
python ai-scanner.py -f json -o report.json   # JSON output
python ai-scanner.py --ci                     # CI mode (exit codes)
python ai-scanner.py --no-recursive           # Single directory only
```

**Exit codes (CI mode):**
- `0` — No issues found
- `1` — Warnings only
- `2` — Critical findings (block build)

---

## CI/CD Integration

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: |
          python ai-scanner.py -d . --ci -f json -o security-report.json
          EXIT=$?
          [ $EXIT -eq 2 ] && exit 1 || exit 0
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: security-report.json
```

### Pre-commit Hook
```yaml
repos:
  - repo: local
    hooks:
      - id: ai-security-scan
        name: AI Supply Chain Security
        entry: python ai-scanner.py -d . --ci
        language: system
        pass_filenames: false
```

---

## Requirements

- Python 3.8+
- `pyyaml`, `colorama`, `watchdog` (see `requirements.txt`)

## License

MIT-0 — No attribution required

## Author

JavaMaGong — https://github.com/javamagong/ai-supply-chain-security

## Changelog

See `CHANGELOG.md` for version history
