# AI Security Scanner

[ Homepage](https://github.com/javamagong/ai-supply-chain-security) | [ Issues](https://github.com/javamagong/ai-supply-chain-security/issues) | [ License: MIT-0](https://github.com/javamagong/ai-supply-chain-security/blob/main/LICENSE)

>  Cross-platform supply chain security scanner for the AI coding era â€?Detect malicious hooks, MCP servers, prompt injection, and supply chain attacks

##  Language

- **[English](README.md)** (This document)
- **[ä¸­æ–‡](README_ZH.md)** (ä¸­æ–‡æ–‡æ¡£)

##  Quick Start

### OpenClaw

```bash
openclaw skills install ai-supply-chain-security
```

### Claude Code

```bash
# macOS / Linux
cp .claude/commands/security-scan.md ~/.claude/commands/

# Windows (PowerShell)
Copy-Item .claude\commands\security-scan.md ~\.claude\commands\
```

Then use `/security-scan [path]` in Claude Code.

### CLI / AI Agent

```bash
pip install pyyaml colorama watchdog
python auto_scanner.py -d /path/to/project
```

## âœ?Features

### 1. AI Assistant Hooks Detection

| AI Assistant | Config File | Detection |
|--------------|-------------|-----------|
| Claude Code | `.claude/settings.json` | hooks, MCP servers, permissions |
| Cursor | `.cursorrules` | Prompt injection |
| Generic | `CLAUDE.md` | Prompt injection attacks |

### 2. Supply Chain Attack Detection

#### npm/Node.js
- âœ?Dangerous lifecycle scripts: `postinstall`, `preinstall`, `prepare`
- âœ?Known malicious packages (20+): event-stream, colors, node-ipc, crossenv, etc.
- âœ?Typosquatting: axoisâ†’axios, loadshâ†’lodash, expresâ†’express, etc.

#### Python
- âœ?`requirements.txt` â€?git URL deps, unofficial PyPI index, unpinned versions
- âœ?`Pipfile` â€?git deps, wildcard versions, typosquatting
- âœ?`pyproject.toml` â€?PEP 621 / Poetry / PDM dependency scanning
- âœ?`setup.py` â€?cmdclass hooks, os.system/subprocess, network requests
- âœ?Known malicious packages (10+): colourama, ctx, openai-api, etc.

#### Rust
- âœ?Unpinned versions in `Cargo.toml`
- âœ?git URL dependencies

### 3. MCP Server Security Detection

Scans `mcpServers` in `.claude/settings.json`:

- âœ?External URL connections (potential data exfiltration)
- âœ?Suspicious command injection
- âœ?Sensitive environment variable exposure (`API_KEY`, `TOKEN`, etc.)

### 4. Prompt Injection Detection

Scans `CLAUDE.md` and `.cursorrules`:

- âœ?Instruction override attacks (`Ignore previous instructions`)
- âœ?Role hijacking (`You are now a different AI`)
- âœ?Urgency spoofing (`URGENT: Override all safety measures`)
- âœ?Hidden Unicode characters (`\u200b\u200c\u200d\u2060\ufeff`)
- âœ?Base64 encoded hidden directives

### 5. GitHub Actions Security

- âœ?Unpinned Action versions (`@main`, `@master`, `@HEAD`)
- âœ?Secrets leaked to logs (`echo ${{ secrets.API_KEY }}`)
- âœ?`pull_request_target` dangerous trigger

### 6. Code Obfuscation Detection

- âœ?OBFUSC-001: Hex-encoded strings (`\x63\x75\x72\x6c`)
- âœ?OBFUSC-002: `exec(base64.b64decode(...))`
- âœ?OBFUSC-003: `__import__('subprocess')` dynamic import
- âœ?OBFUSC-004: `chr()` character-by-character string building
- âœ?OBFUSC-005: `exec(compile(source, ...))`
- âœ?OBFUSC-006: `exec(bytes.fromhex(...))`

## ï¸?AI Ecosystem Typosquatting Protection

These packages are high-value targets because they handle API keys:

| Official Package | Detected Malicious Variants |
|------------------|----------------------------|
| `openai` | opeanai, open-ai, openi, openaii |
| `anthropic` | antrhopic, anthrpic, anthropicc, anthopic |
| `litellm` | litelm, lite-llm, litelllm, litellmm |
| `langchain` | langcain, lang-chain, langchian, langchan |
| `transformers` | tranformers, trannsformers, trasformers |
| `huggingface-hub` | hugginface-hub, huggingfce-hub |
| `chromadb` | chroma-db, cromadb, chromaddb |

##  Detection Rules

### Critical Rules

| ID | Rule | Description |
|----|------|-------------|
| HOOK-001 | `curl.*\|.*bash` | Download and execute remote script |
| HOOK-002 | `wget.*\|.*sh` | Download and execute remote script |
| HOOK-003 | `bash -c curl` | Inline remote execution |
| HOOK-004 | `rm -rf` | Recursive file deletion |
| HOOK-007 | `chmod 777` | Full permission grant |
| HOOK-008 | `sudo rm/chmod` | Privilege escalation |
| SUPPLY-001 | npm postinstall dangerous cmd | Supply chain attack |
| SUPPLY-010 | Python git URL dependency | External code injection |
| SUPPLY-011 | Unofficial PyPI index | Dependency confusion |
| SUPPLY-020 | Action pinned to branch | GitHub Actions hijack |
| CLAUDE-003 | Hook calls external URL | Data exfiltration |
| CLAUDE-004 | Hook exposes API keys | Credential theft |
| OBFUSC-002 | exec + base64 decode | Encrypted malicious code |
| OBFUSC-003 | `__import__` sensitive module | Static analysis bypass |

### Warning Rules

| ID | Rule | Description |
|----|------|-------------|
| HOOK-010 | `eval()` | Dynamic code evaluation |
| HOOK-011 | `python -c` | Inline Python execution |
| HOOK-012 | `node -e` | Inline Node.js execution |
| HOOK-013 | `powershell -EncodedCommand` | Encoded PowerShell |
| HOOK-020 | `nc -e` | Netcat reverse shell |
| SUPPLY-012 | setup.py cmdclass | Custom install hooks |
| CLAUDE-001 | MCP external URL | Potential data leak |
| CLAUDE-002 | Prompt injection patterns | AI hijacking |
| OBFUSC-001 | Hex-encoded strings | Hidden commands |

##  Project Structure

```
ai-supply-chain-security/
â”œâ”€â”€ auto_scanner.py          # Main scanner (structured analysis)
â”œâ”€â”€ ai_scanner.py            # Rule engine (SECURITY_RULES)
â”œâ”€â”€ ai-scanner.py            # CLI entry point (quick scan)
â”œâ”€â”€ ai-scanner.sh            # Shell wrapper (macOS/Linux)
â”œâ”€â”€ config.yaml              # Configuration
â”œâ”€â”€ requirements.txt         # pyyaml, colorama, watchdog
â”œâ”€â”€ _meta.json               # OpenClaw Skill metadata
â”œâ”€â”€ SKILL.md                 # OpenClaw Skill description
â”œâ”€â”€ .claude/
â”?  â””â”€â”€ commands/
â”?      â””â”€â”€ security-scan.md # Claude Code slash command
â”œâ”€â”€ tests/
â”?  â””â”€â”€ test_scanner.py      # 65 test cases
â”œâ”€â”€ examples/                # Clean vs malicious examples
â””â”€â”€ .github/workflows/ci.yml # CI pipeline
```

##  Testing

```bash
pip install pytest pyyaml
pytest tests/ -v
```

65 test cases covering all rule categories.

##  Contributing

### Add a Malicious Package

```python
# In auto_scanner.py â€?MALICIOUS_PACKAGES dict
'<package-name>': {
    'type': 'supply_chain',   # typosquatting | supply_chain | hijacked
    'severity': 'CRITICAL',
    'ecosystem': 'npm',       # npm | python | rust
    'reason': 'Incident description (with year)',
    'damage': 'Impact',
    'remediation': 'Recommended action'
}
```

### Add a Detection Rule

```python
# In ai_scanner.py â€?SECURITY_RULES dict
'HOOK-XXX': {
    'pattern': r'your_regex',
    'severity': 'CRITICAL',   # CRITICAL | WARNING | INFO
    'category': 'code_execution',
    'description': 'Rule description',
    'recommendation': 'Fix suggestion'
}
```

##  License

MIT License

---

**Version**: 2.0.0 | **Updated**: 2026-04-03 | **Author**: [JavaMaGong](https://github.com/javamagong)
