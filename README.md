# AI Security Scanner

[Homepage](https://github.com/javamagong/ai-supply-chain-security) | [Issues](https://github.com/javamagong/ai-supply-chain-security/issues) | [License: MIT-0](https://github.com/javamagong/ai-supply-chain-security/blob/main/LICENSE)

Cross-platform supply chain security scanner for the AI coding era - Detect malicious hooks, MCP servers, prompt injection, and supply chain attacks

## Language

- [English](README.md) (This document)
- [中文](README_ZH.md)

## Quick Start

### OpenClaw
```bash
openclaw skills install ai-supply-chain-security
```

### Manual Installation
```bash
git clone https://github.com/javamagong/ai-supply-chain-security.git
cd ai-supply-chain-security
python ai_scanner.py --help
```

## Features

### 1. AI Assistant Hooks Detection
Detect malicious configurations in `.claude/settings.json`, `.cursorrules`, and `CLAUDE.md`

### 2. MCP Server Security
Scan MCP server configurations for potential security risks

### 3. Prompt Injection Detection
Identify prompt injection attacks and hidden malicious instructions

### 4. Supply Chain Security
- npm package vulnerability detection
- PyPI package security scanning
- Rust crate analysis
- Dependency confusion attack protection

### 5. Typosquatting Protection
Detect typosquatted packages targeting AI ecosystem (openai, anthropic, litellm, langchain, etc.)

## CLI Usage

```bash
# Scan current directory
python ai_scanner.py

# Scan specific directory
python ai_scanner.py -d /path/to/project

# Full scan with auto-discovery
python auto_scanner.py

# Generate JSON report
python ai_scanner.py -f json -o report.json
```

## Configuration

Edit `config.yaml` to customize:
- Scan paths
- Notification settings (SMTP, Webhook)
- Severity thresholds
- Custom detection rules

## Requirements

- Python 3.8+
- See `requirements.txt` for dependencies

## License

MIT-0 - See [LICENSE](LICENSE)

## Author

JavaMaGong - [GitHub](https://github.com/javamagong)
