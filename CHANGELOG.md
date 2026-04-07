# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

