# AI Security Scanner

[🏠 Website](https://github.com/javamagong/ai-security-scanner) | [📦 Issues](https://github.com/javamagong/ai-security-scanner/issues) | [📄 License: MIT](https://github.com/javamagong/ai-security-scanner/blob/main/LICENSE)

> 🔒 Cross-platform AI Coding security scanner - Detect malicious hooks, MCP servers, and supply chain attacks

## 🌐 Language

- [English](PROJECT-INTRO.md)
- [中文](PROJECT-INTRO_ZH.md)

## ✨ Features

### 1. AI Assistant Hooks Detection

| AI Assistant | Config File | Detection |
|---------------|-------------|-----------|
| Claude Code | `.claude/settings.json` | hooks, MCP servers, permissions |
| Claude Code | `.claude/config.json` | hooks configuration |
| Cursor | `.cursorrules` | Prompt injection |
| Generic | `CLAUDE.md` | Prompt injection attacks |

### 2. Supply Chain Attack Detection

#### npm/Node.js
- ✅ Dangerous scripts: `postinstall`, `preinstall`, `prepare`
- ✅ Known malicious packages (20+ packages)
- ✅ Typosquatting attacks

#### Python
- ✅ Git URL dependencies detection
- ✅ Unofficial PyPI index (dependency confusion)
- ✅ Unpinned versions
- ✅ `setup.py` malicious code detection
- ✅ `pyproject.toml` suspicious build backend

#### Rust
- ✅ Unpinned versions in `Cargo.toml`
- ✅ Git URL dependencies

### 3. MCP Server Security Detection

Detect `mcpServers` in `.claude/settings.json`:

- ✅ External URL connection detection
- ✅ Suspicious command injection
- ✅ Sensitive environment variable exposure

### 4. Prompt Injection Detection

Detect in `CLAUDE.md` and `.cursorrules`:

- ✅ Instruction override attacks
- ✅ Role playing attacks
- ✅ Emergency instruction disguise
- ✅ Hidden Unicode characters
- ✅ Base64 encoded content

### 5. GitHub Actions Security

- ✅ Unpinned Action versions (using branch names)
- ✅ Secrets exposure to logs
- ✅ `pull_request_target` dangerous trigger

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/javamagong/ai-security-scanner.git
cd ai-security-scanner
pip install -r requirements.txt
```

### Usage

```bash
# Scan current directory
python ai-scanner.py

# Scan specific directory
python ai-scanner.py -d /path/to/project

# JSON output
python ai-scanner.py -f json -o report.json

# Watch mode
python ai-scanner.py --watch --interval 60

# CI/CD mode
python ai-scanner.py --ci
```

### Shell Version (macOS/Linux)

```bash
chmod +x ai-scanner.sh
./ai-scanner.sh -d /path/to/project
```

## 🔍 Detection Rules

### Critical Rules

| ID | Rule | Description |
|----|------|-------------|
| HOOK-001 | `curl.*\|.*bash` | Download and execute remote script |
| HOOK-002 | `wget.*\|.*sh` | Download and execute remote script |
| HOOK-003 | `rm -rf` | Recursive delete |
| SUPPLY-001 | npm postinstall dangerous commands | Supply chain attack |
| SUPPLY-002 | Python git URL dependency | External code injection |
| SUPPLY-003 | Unofficial PyPI index | Dependency confusion |
| MCP-001 | MCP server external URL | Data exfiltration |
| MCP-002 | MCP command injection | Remote code execution |
| PROMPT-001 | Instruction override | Prompt injection |

### Warning Rules

| ID | Rule | Description |
|----|------|-------------|
| HOOK-010 | `python -c` | Execute Python code |
| HOOK-011 | `node -e` | Execute Node.js code |
| SUPPLY-010 | Unpinned version | Version hijacking |
| MCP-003 | MCP credential exposure | Sensitive info leak |

## 🛡️ Known Malicious Packages

### npm Ecosystem (20+ packages)

| Package | Incident | Impact |
|---------|----------|--------|
| event-stream | 2018 | Stole Bitcoin wallet keys |
| flatmap-stream | 2018 | Injected mining code |
| crossenv | 2021 | Stole environment credentials |
| ua-parser-js | 2021 | Stole browser passwords |
| colors | 2022 | Corrupted production |
| node-ipc | 2022 | Deleted files in certain regions |

### PyPI Ecosystem (10+ packages)

| Package | Type | Impact |
|---------|------|--------|
| colourama | Typosquatting | Credential theft |
| python3-dateutil | Typosquatting | Backdoor injection |
| jeIlyfish | Unicode confusion | SSH key theft |
| ctx | Package hijacking | Environment variable theft |
| openai-api | Typosquatting | OpenAI API Key theft |

### AI Ecosystem Protection

| Official Package | Malicious Variants |
|------------------|-------------------|
| openai | opeanai, open-ai, openaii |
| anthropic | antrhopic, anthropicc |
| litellm | litelm, lite-llm, litelllm |
| langchain | langcain, lang-chain |
| transformers | tranformers, trannsformers |

## 📊 Output Example

```
============================================================
AI Security Scanner v2.0 - Comprehensive Report
============================================================

[Projects Found]: 1
  - /path/to/project
    Types: npm, python

[AI Config Security]: 2 issues
  [CRITICAL] MCP server connects to external address
    File: /path/to/.claude/settings.json
    Fix: Verify if MCP server is trusted

[Dependency Issues]: 3 issues
  [CRITICAL] Python dependency installed via git URL
    File: /path/to/requirements.txt:5
    Fix: Use PyPI pinned version instead

[Summary]
  Total issues:     5
  Critical:         2
  Warning:          3

============================================================
```

## 🔧 Configuration

```yaml
# config.yaml
scan_paths:
  - ~/projects
  - ~/work

exclude_patterns:
  - "**/node_modules/**"
  - "**/dist/**"

rules:
  enabled:
    - HOOK-001
    - HOOK-002
    - SUPPLY-001
    - SUPPLY-002
    - MCP-001

ci:
  fail_on_critical: true
  fail_on_warning: false
```

## 📁 Project Structure

```
ai-security-scanner/
├── ai-scanner.py           # Python CLI entry point
├── ai-scanner.sh           # Shell wrapper (macOS/Linux)
├── ai-scanner.js           # Node.js version
├── ai_scanner.py           # Core scanner module
├── auto_scanner.py         # Auto-detection module
├── config.yaml             # Configuration
├── requirements.txt        # Python dependencies
├── _meta.json             # ClawHub metadata
├── SKILL.md               # Skill documentation
├── PROJECT-INTRO.md       # Project introduction (EN)
├── PROJECT-INTRO_ZH.md    # Project introduction (ZH)
├── INSTALL.md             # Installation guide
├── LICENSE                # MIT License
├── examples/              # Example files
├── tests/                 # Test cases
└── .github/workflows/      # GitHub Actions CI
```

## 🧪 Testing

```bash
# Run tests
pytest tests/ -v

# Scan examples
python ai-scanner.py -d examples --no-recursive
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Commit changes
4. Push to branch
5. Open a Pull Request

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SLSA Framework](https://slsa.dev/)
- [npm Security](https://docs.npmjs.com/cli/v9/using-npm/security)
- [Socket Security](https://socket.dev/)

---

**Version**: 2.0.0  
**Updated**: 2026-04-02  
**Author**: [JavaMaGong](https://github.com/javamagong)
