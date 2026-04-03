# AI Security Scanner Skill

Cross-platform AI Coding security scanner for **OpenClaw** and **Claude Code**, detecting hooks configuration risks, MCP server attacks, prompt injection, and supply chain attacks (npm/PyPI/Rust).

## Skill Information

```yaml
name: ai-supply-chain-security
version: 2.0.0
description: Cross-platform AI Coding security scanner - Detect hooks, MCP servers, prompt injection, and supply chain attacks
author: JavaMaGong
platforms: [Windows, macOS, Linux]
category: security
```

## Installation

### OpenClaw
```bash
openclaw skills install ai-supply-chain-security
```

### Manual Installation
```bash
# Clone repository
git clone https://github.com/javamagong/ai-supply-chain-security.git

# Run directly (no install script needed)
python ai-scanner.py --help
```

## Core Features

### 1. AI Assistant Hooks Detection

| AI Assistant | Config File | Detection Content |
|-------------|-------------|-------------------|
| Claude Code | `.claude/settings.json` | hooks, MCP servers, permissions |
| Cursor | `.cursorrules` | Prompt injection |
| Generic | `CLAUDE.md` | Prompt injection attacks |

### 2. MCP Server Security Detection

Scans MCP server configurations for:
- Unverified server sources
- Excessive permission requests
- Suspicious environment variable access

### 3. Prompt Injection Detection

Detects suspicious patterns in `CLAUDE.md` and `.cursorrules`:

- Instruction override patterns (e.g., phrases attempting to clear previous context)
- Role hijacking attempts (e.g., claims to change AI identity)
- Fake urgency commands (e.g., URGENT override requests)
- Hidden Unicode characters (zero-width chars like U+200B, U+200C, U+200D)
- Base64 encoded hidden instructions

### 4. Supply Chain Security Detection

**npm Packages:**
- Known malicious packages (colors, coa, rc, etc.)
- Dangerous lifecycle scripts (postinstall, preinstall, prepare)
- Dependency confusion attacks
- Typosquatting (opeanai, litelm, etc.)

**Python Packages:**
- Malicious code in setup.py
- Suspicious pyproject.toml configurations
- Git URL dependencies with risks
- Dependency confusion attacks

**Rust Crates:**
- Build.rs malicious code
- Suspicious cargo.toml

### 5. GitHub Actions Security

- Unpinned Action versions (@main, @master, @HEAD)
- Secrets leakage to logs
- Dangerous pull_request_target triggers

### 6. Code Obfuscation Detection

- Hex-encoded malicious code
- Base64 hidden payloads
- Unicode homograph attacks

## CLI Usage

### Basic Scan
```bash
# Scan current directory
python ai_scanner.py

# Scan specific directory
python ai_scanner.py -d /path/to/project

# Full scan with node_modules
python ai_scanner.py -d /path/to/project --full
```

### Auto-Discovery Scan
```bash
# Scan all projects under directory
python auto_scanner.py -d /path/to/projects

# Scan with specific severity filter
python auto_scanner.py -d /path/to/projects --severity critical
```

### Output Formats
```bash
# Text output (default)
python ai_scanner.py -f text

# JSON output
python ai_scanner.py -f json -o report.json

# Markdown report
python ai_scanner.py -f markdown -o report.md
```

## Configuration

Edit `config.yaml`:

```yaml
scan_paths:
  - "./"
  - "../projects"

notification:
  webhook:
    enabled: false
    url: "${SECURITY_WEBHOOK_URL}"
  email:
    enabled: false
    smtp_host: "${SMTP_HOST}"
    smtp_port: 587
    from: "${SMTP_FROM}"
    to: "${SMTP_TO}"
    password: "${SMTP_PASSWORD}"

severity_threshold: "medium"

auto_fix: false
```

## Detection Rules

### Known Malicious npm Packages
- colors (>=1.4.0)
- coa (>=2.0.0)
- rc (>=1.3.0)
- And 30+ more...

### AI Ecosystem Typosquatting Targets
- openai / opeanai
- anthropic / anthorpic
- litellm / litelm
- langchain / langchn

### Dangerous Patterns
- Hidden Unicode: zero-width chars in filenames/code
- Suspicious base64: encoded shell commands
- Malicious setup.py: exec() calls, network requests

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  uses: actions/checkout@v3
  
- name: Run AI Security Scanner
  run: |
    pip install -r requirements.txt
    python ai_scanner.py -d . -f json -o security-report.json
    
- name: Upload Report
  uses: actions/upload-artifact@v3
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
        name: AI Security Scanner
        entry: python ai_scanner.py -d .
        language: system
        pass_filenames: false
```

## Requirements

- Python 3.8+
- See `requirements.txt` for dependencies

## License

MIT-0 - See LICENSE file

## Author

JavaMaGong - https://github.com/javamagong

## Changelog

See CHANGELOG.md for version history
