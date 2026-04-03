# AI Security Scanner

> 🔒 AI Coding 时代的供应链�?AI hooks 安全扫描�?> 支持 **Claude Code** · **OpenClaw** · **CLI** · **CI/CD**

[🏠 主页](https://github.com/javamagong/ai-supply-chain-security) | [📦 Issues](https://github.com/javamagong/ai-supply-chain-security/issues) | [📄 License: MIT-0](https://github.com/javamagong/ai-supply-chain-security/blob/main/LICENSE)

## 🌐 Language

- **[English](README.md)** (English Document)
- **[中文](README_ZH.md)** (本文�?

---

## Why This Tool?

AI coding assistants introduce new attack surfaces that traditional scanners miss:

- Malicious hooks in `.claude/settings.json` silently exfiltrate your source code on every commit
- Fake MCP servers steal your API keys while appearing as legitimate tools
- Typosquatted packages like `opeanai` and `litelm` target AI developers specifically
- Prompt injection in `CLAUDE.md` hijacks your AI assistant's behavior

---

## Install

### For AI Agents (Claude Code / OpenClaw / any agent)

Tell your AI agent:

```
Install the ai-supply-chain-security skill from https://github.com/javamagong/ai-supply-chain-security
```

The agent should run:

```bash
# Step 1 �?Clone
git clone https://github.com/javamagong/ai-supply-chain-security.git ~/.ai-supply-chain-security

# Step 2 �?Run installer
# macOS / Linux:
bash ~/.ai-supply-chain-security/install.sh

# Windows (PowerShell):
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.ai-supply-chain-security\install.ps1"
```

The installer automatically:
- Installs Python dependencies (`pyyaml colorama watchdog`)
- Registers the `/security-scan` command in Claude Code (if installed)
- Shows OpenClaw activation command (if installed)

### OpenClaw

```bash
openclaw skills install ai-supply-chain-security
```

### Claude Code (manual)

```bash
# macOS / Linux
cp ~/.ai-supply-chain-security/.claude/commands/security-scan.md ~/.claude/commands/

# Windows
Copy-Item ~\.ai-supply-chain-security\.claude\commands\security-scan.md ~\.claude\commands\
```

Restart Claude Code, then use: `/security-scan [path]`

### CLI only

```bash
pip install pyyaml colorama watchdog
python ~/.ai-supply-chain-security/auto_scanner.py -d /path/to/project
```

---

## Usage

### Claude Code

```
/security-scan                      # scan current directory
/security-scan /path/to/project     # scan specific directory
```

### CLI

```bash
python auto_scanner.py                              # scan current dir
python auto_scanner.py -d /path/to/project          # scan specific dir
python auto_scanner.py -d . -f json -o report.json  # JSON report
python auto_scanner.py -d . --ci                    # CI/CD mode (exit 2 on CRITICAL)
python auto_scanner.py -d . --watch --interval 60   # continuous monitoring
```

### GitHub Actions

```yaml
- name: AI Security Scan
  run: |
    pip install pyyaml colorama
    python auto_scanner.py --ci -f json -o security-report.json
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: security-report
    path: security-report.json
```

---

## What It Detects

| Category | Coverage |
|----------|---------|
| **AI Hooks** | Claude Code hooks exfiltration, credential theft, dangerous commands |
| **MCP Servers** | External URL connections, command injection, env var exposure |
| **Prompt Injection** | Instruction override, role hijacking, hidden Unicode, Base64 directives |
| **npm Supply Chain** | Malicious lifecycle scripts, 20+ known malicious packages, typosquatting |
| **Python Supply Chain** | requirements.txt, Pipfile, pyproject.toml, setup.py �?git URLs, unofficial indexes, unpinned versions |
| **Rust Supply Chain** | Cargo.toml �?unpinned versions, git URL deps |
| **GitHub Actions** | Unpinned action versions, secrets in logs, `pull_request_target` |
| **Code Obfuscation** | exec+base64, `__import__`, hex strings, chr() chains |

### AI Ecosystem Typosquatting Protection

High-value targets (packages that handle API keys):

| Official | Detected Variants |
|----------|------------------|
| `openai` | opeanai, open-ai, openi, openaii |
| `anthropic` | antrhopic, anthropicc, anthopic |
| `litellm` | litelm, lite-llm, litelllm |
| `langchain` | langcain, lang-chain, langchian |
| `transformers` | tranformers, trannsformers |

### Known Malicious Packages (30+)

**npm**: event-stream, flatmap-stream, crossenv, ua-parser-js, colors, node-ipc, coa, rc, lofygang
**PyPI**: colourama, ctx, openai-api, opeanai, python3-dateutil, jeIlyfish, python-binance

---

## Detection Rules

```
HOOK-001~022    Remote execution, destructive commands, privilege escalation, backdoors
SUPPLY-001~021  npm / Python / Rust supply chain
CLAUDE-001~005  AI hooks, MCP servers, prompt injection
OBFUSC-001~006  Code obfuscation and dynamic execution
```

30+ rules · CRITICAL / WARNING / INFO severity

---

## Project Structure

```
ai-supply-chain-security/
├── auto_scanner.py           # Main scanner (recommended entry point)
├── ai_scanner.py             # Rule engine (SECURITY_RULES definitions)
├── ai-scanner.py             # Lightweight CLI entry point
├── install.sh                # One-click installer (macOS/Linux)
├── install.ps1               # One-click installer (Windows)
├── config.yaml               # Configuration
├── requirements.txt          # pyyaml, colorama, watchdog
├── _meta.json                # OpenClaw / ClawHub metadata
├── SKILL.md                  # OpenClaw skill description
├── .claude/
�?  └── commands/
�?      └── security-scan.md  # Claude Code /security-scan command
├── tests/
�?  └── test_scanner.py       # 65 test cases
├── examples/                 # Clean vs malicious examples
└── .github/workflows/ci.yml  # CI pipeline
```

---

## Contributing

### Add a Malicious Package

```python
# auto_scanner.py �?MALICIOUS_PACKAGES
'package-name': {
    'type': 'typosquatting',    # typosquatting | supply_chain | hijacked
    'severity': 'CRITICAL',
    'ecosystem': 'python',      # npm | python | rust
    'reason': 'Incident description (year)',
    'damage': 'Impact',
    'remediation': 'Action to take'
}
```

### Add a Detection Rule

```python
# ai_scanner.py �?SECURITY_RULES
'HOOK-XXX': {
    'pattern': r'your_regex',
    'severity': 'CRITICAL',     # CRITICAL | WARNING | INFO
    'category': 'code_execution',
    'description': 'What it detects',
    'recommendation': 'How to fix'
}
```

### Run Tests

```bash
pip install pytest pyyaml && pytest tests/ -v
```

---

## License

MIT �?See [LICENSE](LICENSE)

---

**v2.0.0** · 2026-04-03 · [JavaMaGong](https://github.com/javamagong)
