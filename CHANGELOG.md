# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-04-07

### Added
- **Hardcoded API key / credential detection** (SECRET-001~008):
  - Anthropic (`sk-ant-`), OpenAI (`sk-proj-`), AWS Access Key (`AKIA*`), GitHub PAT (`ghp_`/`github_pat_`), Slack (`xoxb-`), Google (`AIza`), HuggingFace (`hf_`)
  - Scans all source file types; redacts matched value in output
  - Skips test files, `.example`/`.sample` templates, and `node_modules/`
- **Rust `build.rs` compile-time execution scanning** (SUPPLY-022/023):
  - Detects shell/network tool spawning, TCP/UDP connections, file deletion, HTTP client imports, sensitive env var reads
  - Escalates to SUPPLY-023 when `proc-macro = true` co-exists with `build.rs`
- **IDE configuration attack detection** (IDE-001~004):
  - VS Code `tasks.json`: auto-run on folder open, dangerous command execution
  - VS Code `settings.json`: PATH hijacking via `terminal.integrated.env.*`, Python venv auto-activation
  - IntelliJ IDEA `workspace.xml`: dangerous run configurations
- **Makefile / Taskfile build script attack detection** (BUILD-001~003):
  - `curl|bash`, `wget|sh`, `$(shell curl...)`, `$(eval wget...)` patterns
  - Covers `Makefile`, `GNUmakefile`, `Taskfile.yml`, `Taskfile.yaml`
- **Unicode homoglyph package name detection** (SUPPLY-030):
  - Built-in confusables map for Cyrillic, Greek, fullwidth → ASCII transliteration
  - Integrated into npm and Python dependency checks
- **GitHub Actions enhanced detection** (GHAS-001~003):
  - Pwn Request pattern: `pull_request_target` + fork head checkout (CRITICAL)
  - `::set-env` deprecated command injection
  - `::add-path` deprecated PATH injection
  - Untrusted `github.event.pull_request.title/body` in run steps

### Fixed
- Secret scanner now skips test files (`test_*.py`, `*.spec.ts`, files in `tests/` dir) to eliminate false positives
- `check_python_dependencies()` now uses `errors='ignore'` to handle non-UTF-8 package names (homoglyph test support)

### Changed
- Scanner version display updated to v2.2
- SKILL.md comprehensively rewritten to reflect all detection capabilities

## [2.1.0] - 2026-04-03

### Added
- **Lock file poisoning detection**: `package-lock.json` (npm v1/v2/v3), `yarn.lock`, `poetry.lock`, `Cargo.lock`
  - Detects non-official resolved URLs (CRITICAL)
  - Detects missing integrity/checksum hashes (WARNING)
  - Cross-references lock file entries against known malicious package database
  - Detects git-sourced dependencies in lock files
- **Registry substitution attack detection**: `.npmrc`, `pip.conf`/`pip.ini`
  - `.npmrc`: global registry overrides, scoped registry redirects, hardcoded auth tokens, `always-auth=true`
  - `pip.conf`/`pip.ini`: non-official `index-url`, `extra-index-url` dependency confusion risk, `trusted-host` TLS bypass
  - Scans project-level and global config files (`~/.npmrc`, platform-specific pip config)
- Lock files and registry configs added to file change monitoring

### Changed
- All Chinese text in source code and config translated to English

## [2.0.1] - 2026-04-03

### Fixed
- Removed Chinese description from SKILL.md metadata to ensure all documentation is in English
- Replaced explicit prompt injection examples with descriptive explanations to avoid triggering security scanners
- Removed references to missing installer files (install.sh, install.ps1, .claude/commands/security-scan.md)
- Cleaned up package bundle by excluding non-essential files (tests, reports, cache files)

## [2.0.0] - 2026-04-03

### Added
- Cross-platform support (Windows, macOS, Linux)
- AI assistant hooks detection (Claude Code, Cursor)
- MCP server security detection
- Prompt injection attack detection
- Supply chain attack detection for npm, PyPI, and Rust
- Typosquatting protection for AI ecosystem packages (openai, anthropic, litellm, langchain, etc.)
- Version-aware malicious package detection
- GitHub Actions security scanning
- File change monitoring with hash-based detection
- Comprehensive JSON and text reporting
- CI/CD integration support

### Security
- Detection of 30+ known malicious packages
- Protection against dependency confusion attacks
- Detection of dangerous npm lifecycle scripts (postinstall, preinstall, prepare)
- Python setup.py malicious code detection
- Hidden Unicode character detection in prompt files

## [1.0.0] - 2026-04-02

### Added
- Initial release
- Basic hooks configuration detection
- npm package.json scanning
- Python requirements.txt scanning
- Core CLI interface

