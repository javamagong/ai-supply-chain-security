# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

