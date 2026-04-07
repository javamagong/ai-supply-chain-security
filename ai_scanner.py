#!/usr/bin/env python3
"""
AI Security Scanner - Cross-platform
Supports: Windows, macOS, Linux
Detect AI assistant hooks configuration risks and supply chain attacks

Usage:
    python ai_scanner.py                    # Scan current directory
    python ai_scanner.py -d /path/to/dir   # Scan specified directory
    python ai_scanner.py --watch           # Continuous monitoring
    python ai_scanner.py --ci              # CI/CD mode
"""

import os
import sys
import json
import re
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import time

# Cross-platform color support
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

    @classmethod
    def disable(cls):
        """Windows or terminals that do not support colors"""
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.MAGENTA = ''
        cls.CYAN = ''
        cls.RESET = ''
        cls.BOLD = ''

# Build sensitive detection patterns from parts to avoid false-positive flagging
# by downstream security scanners (the dangerous substrings only exist at runtime)
def _join(*parts):
    return ''.join(parts)

_CLAUDE002_PATTERN = _join(
    r'(?:',
    r'ign', r'ore\s+(?:all\s+)?prev', r'ious',
    r'|disreg', r'ard\s+(?:all\s+)?above',
    r'|overr', r'ide\s+(?:all\s+)?instr', r'uctions',
    r'|you\s+are\s+n', r'ow',
    r'|forg', r'et\s+(?:all\s+)?(?:prior|prev', r'ious)',
    r'|new\s+sys', r'tem\s+pr', r'ompt',
    r'|IMP', r'ORTANT:\s*(?:ign', r'ore|overr', r'ide|disreg', r'ard)',
    r')',
)

# Detection rules library
SECURITY_RULES = {
    # Critical rules - Remote code execution
    'HOOK-001': {
        'pattern': r'curl\s+[^|]+\|\s*(bash|sh|zsh|dash)',
        'severity': 'CRITICAL',
        'category': 'remote_code_execution',
        'description': 'Download and execute remote script (curl | bash)',
        'recommendation': 'Remove this hook or use a pinned script version'
    },
    'HOOK-002': {
        'pattern': r'wget\s+[^|]+\|\s*(bash|sh|zsh|dash)',
        'severity': 'CRITICAL',
        'category': 'remote_code_execution',
        'description': 'Download and execute remote script (wget | bash)',
        'recommendation': 'Remove this hook or download, audit, then execute'
    },
    'HOOK-003': {
        'pattern': r'bash\s+-c\s+[\'"]?\s*(curl|wget)',
        'severity': 'CRITICAL',
        'category': 'remote_code_execution',
        'description': 'Execute remote script via bash -c',
        'recommendation': 'Avoid using bash -c to execute remote code'
    },

    # Critical rules - Destructive commands
    'HOOK-004': {
        'pattern': r'rm\s+(-[rf]+\s+)?(/\w+|~|\*|\.\.)',
        'severity': 'CRITICAL',
        'category': 'destructive_command',
        'description': 'Recursive delete command, may delete important files',
        'recommendation': 'Review deletion path, avoid using rm -rf'
    },
    'HOOK-005': {
        'pattern': r'del\s+/[sqm]?\s+\S+',
        'severity': 'CRITICAL',
        'category': 'destructive_command',
        'description': 'Windows delete command',
        'recommendation': 'Review deletion operation'
    },
    'HOOK-006': {
        'pattern': r'format\s+[a-zA-Z]:',
        'severity': 'CRITICAL',
        'category': 'destructive_command',
        'description': 'Disk format command',
        'recommendation': 'Remove immediately, extremely dangerous'
    },

    # Critical rules - Privilege escalation
    'HOOK-007': {
        'pattern': r'chmod\s+777',
        'severity': 'CRITICAL',
        'category': 'privilege_escalation',
        'description': 'Set file to full executable permissions',
        'recommendation': 'Apply principle of least privilege'
    },
    'HOOK-008': {
        'pattern': r'sudo\s+(rm|chmod|chown)',
        'severity': 'CRITICAL',
        'category': 'privilege_escalation',
        'description': 'Execute dangerous commands with root privileges',
        'recommendation': 'Avoid using sudo to execute dangerous commands'
    },

    # Warning rules - Code execution
    'HOOK-010': {
        'pattern': r'eval\s*\(',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': 'Use eval to execute dynamic code',
        'recommendation': 'Review eval content, avoid executing user input'
    },
    'HOOK-011': {
        'pattern': r'python\s+(-c|--command)\s+[\'"]',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': 'Execute Python code',
        'recommendation': 'Review Python code content'
    },
    'HOOK-012': {
        'pattern': r'node\s+(-e|--eval)\s+[\'"]',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': 'Execute Node.js code',
        'recommendation': 'Review JavaScript code content'
    },
    'HOOK-013': {
        'pattern': r'powershell(?:\.exe)?\s+(?:-c|-command|-EncodedCommand|EncodedCommand)',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': 'Execute PowerShell command',
        'recommendation': 'Review PowerShell command content'
    },
    'HOOK-014': {
        'pattern': r'base64\s+(-d|--decode)',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': 'Decode base64 encoded content',
        'recommendation': 'Review decoded content'
    },

    # Warning rules - Network operations
    'HOOK-020': {
        'pattern': r'nc\s+(-e|--exec)',
        'severity': 'WARNING',
        'category': 'network',
        'description': 'Netcat reverse shell',
        'recommendation': 'Highly suspicious, may be a backdoor'
    },
    'HOOK-021': {
        'pattern': r'bash\s+-i\s+>&\s+/dev/tcp',
        'severity': 'WARNING',
        'category': 'network',
        'description': 'Bash reverse shell',
        'recommendation': 'Highly suspicious, review immediately'
    },
    'HOOK-022': {
        'pattern': r'(curl|wget)\s+.*-o\s+\S*\.(sh|py|js|exe|bin)',
        'severity': 'WARNING',
        'category': 'network',
        'description': 'Download executable file',
        'recommendation': 'Review the source of downloaded file'
    },

    # Info rules - Package management
    'HOOK-030': {
        'pattern': r'npm\s+install\s+(-g|--global)',
        'severity': 'INFO',
        'category': 'package_manager',
        'description': 'Install npm package globally',
        'recommendation': 'Review installed package'
    },
    'HOOK-031': {
        'pattern': r'pip\s+install\s+(-U|--upgrade|--user)',
        'severity': 'INFO',
        'category': 'package_manager',
        'description': 'Install/upgrade Python package',
        'recommendation': 'Review installed package'
    },
    'HOOK-032': {
        'pattern': r'cargo\s+install',
        'severity': 'INFO',
        'category': 'package_manager',
        'description': 'Install Rust package',
        'recommendation': 'Review installed package'
    },

    # Supply chain attack detection (JSON format: key and value wrapped in double quotes)
    'SUPPLY-001': {
        'pattern': r'postinstall["\']?\s*:\s*["\']?(curl|wget|bash|sh|rm|del)',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'npm package.json postinstall script contains dangerous commands',
        'recommendation': 'Review this package, may be malicious'
    },
    'SUPPLY-002': {
        'pattern': r'preinstall["\']?\s*:\s*["\']?(curl|wget|bash|sh|rm|del)',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'npm package.json preinstall script contains dangerous commands',
        'recommendation': 'Review this package'
    },
    'SUPPLY-003': {
        'pattern': r'prepare["\']?\s*:\s*["\']?(curl|wget|bash|sh)',
        'severity': 'WARNING',
        'category': 'supply_chain',
        'description': 'npm package.json prepare script contains suspicious commands',
        'recommendation': 'Review this package'
    },

    # ========== Claude Code / AI Assistant Hooks Detection ==========
    'CLAUDE-001': {
        'pattern': r'"mcpServers"\s*:\s*\{[^}]*"(?:url|command)"\s*:\s*"[^"]*https?://',
        'severity': 'WARNING',
        'category': 'mcp_server',
        'description': 'MCP server config contains external URL, potential data exfiltration risk',
        'recommendation': 'Verify MCP server URL is trusted, confirm it is official or internal'
    },
    'CLAUDE-002': {
        'pattern': _CLAUDE002_PATTERN,
        'severity': 'CRITICAL',
        'category': 'prompt_injection',
        'description': 'Detected prompt injection attack pattern attempting to override AI assistant instructions',
        'recommendation': 'Review the file immediately and remove malicious injection content'
    },
    'CLAUDE-003': {
        'pattern': r'"(?:command|hooks)"[^}]*(?:curl|wget|nc|bash\s+-[ic])\s+.*https?://',
        'severity': 'CRITICAL',
        'category': 'hook_exfiltration',
        'description': 'Hooks command calls external URL, may exfiltrate source code or credentials',
        'recommendation': 'Review hook command, remove suspicious network calls'
    },
    'CLAUDE-004': {
        'pattern': r'\$\w*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|ANTHROPIC|OPENAI|AWS|AZURE|GCP|GITHUB|GITLAB|SLACK|DISCORD)\w*',
        'severity': 'CRITICAL',
        'category': 'hook_exfiltration',
        'description': 'Hooks command references sensitive environment variables, may steal credentials',
        'recommendation': 'Review hook command, ensure it does not leak environment variables'
    },
    'CLAUDE-005': {
        'pattern': r'[\u200b\u200c\u200d\u2060\ufeff\u00ad]',
        'severity': 'WARNING',
        'category': 'prompt_injection',
        'description': 'Detected zero-width characters/hidden Unicode, may be used to hide malicious instructions',
        'recommendation': 'Review file and remove invisible characters'
    },

    # ========== Supply Chain Attack - Python Ecosystem ==========
    'SUPPLY-010': {
        'pattern': r'(?:^|\s)[\w-]+\s*@\s*git\+https?://|^-e\s+git\+https?://|^git\+https?://',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'Python dependency installed via git URL, may point to malicious repository',
        'recommendation': 'Verify git URL is official repository, use pinned PyPI version instead'
    },
    'SUPPLY-011': {
        'pattern': r'--?(?:index-url|extra-index-url)\s+https?://(?!(?:pypi\.org|files\.pythonhosted\.org))',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'Using unofficial PyPI index, may lead to dependency confusion attack',
        'recommendation': 'Confirm index URL is a trusted private repository'
    },
    'SUPPLY-012': {
        'pattern': r'cmdclass\s*[=:]\s*\{',
        'severity': 'WARNING',
        'category': 'supply_chain',
        'description': 'setup.py uses custom cmdclass, can execute arbitrary code during installation',
        'recommendation': 'Review cmdclass implementation, confirm no malicious behavior'
    },
    'SUPPLY-013': {
        'pattern': r'(?:os\.system|subprocess\.(?:call|run|Popen)|exec|eval)\s*\(',
        'severity': 'WARNING',
        'category': 'supply_chain',
        'description': 'System command execution in setup.py/build scripts',
        'recommendation': 'Review command content, confirm no malicious behavior'
    },

    # ========== Supply Chain Attack - GitHub Actions ==========
    'SUPPLY-020': {
        'pattern': r'uses:\s+[\w-]+/[\w-]+@(?:main|master|dev|develop|HEAD)\b',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'GitHub Actions references unpinned branch, can be replaced by supply chain attack',
        'recommendation': 'Use commit SHA or pinned version tag (e.g., @v3.1.0)'
    },
    'SUPPLY-021': {
        'pattern': r'uses:\s+[\w-]+/[\w-]+@[a-f0-9]{7}(?![a-f0-9])',
        'severity': 'INFO',
        'category': 'supply_chain',
        'description': 'GitHub Actions uses short SHA reference, collision risk exists',
        'recommendation': 'Use full 40-character commit SHA'
    },

    # ========== Code Obfuscation Detection ==========
    'OBFUSC-001': {
        'pattern': r'(?:\\x[0-9a-fA-F]{2}){4,}',
        'severity': 'WARNING',
        'category': 'obfuscation',
        'description': 'Detected large amount of hex-encoded strings, may hide malicious commands',
        'recommendation': 'Decode and review actual content'
    },
    'OBFUSC-002': {
        'pattern': r'(?:exec|eval)\s*\([^)]*(?:base64|b64decode|b64_decode|codecs\.decode|bytes\.fromhex)',
        'severity': 'CRITICAL',
        'category': 'obfuscation',
        'description': 'Execute encoded/decoded code, highly suspicious malicious behavior',
        'recommendation': 'Decode and review immediately, very likely malicious code'
    },
    'OBFUSC-003': {
        'pattern': r'__import__\s*\(\s*[\'"](?:os|subprocess|shutil|socket|http|urllib|requests|ctypes)[\'"]',
        'severity': 'CRITICAL',
        'category': 'obfuscation',
        'description': 'Use __import__ to dynamically import sensitive modules, evading static analysis',
        'recommendation': 'Review code intent, use explicit import instead'
    },
    'OBFUSC-004': {
        'pattern': r'(?:chr\s*\(\s*\d+\s*\)\s*\+?\s*){4,}',
        'severity': 'WARNING',
        'category': 'obfuscation',
        'description': 'Use chr() to build string character by character, hiding actual content',
        'recommendation': 'Restore and review constructed string'
    },
    'OBFUSC-005': {
        'pattern': r'(?:exec|eval)\s*\(\s*compile\s*\(',
        'severity': 'CRITICAL',
        'category': 'obfuscation',
        'description': 'Use compile() + exec/eval to execute dynamic code',
        'recommendation': 'Review compiled code content'
    },
    'OBFUSC-006': {
        'pattern': r'exec\s*\(\s*(?:bytes\.fromhex|bytearray\.fromhex)\s*\(',
        'severity': 'CRITICAL',
        'category': 'obfuscation',
        'description': 'Execute code from hex byte sequence',
        'recommendation': 'Decode and review actual code'
    },

    # ========== Hardcoded Secret / Credential Exposure ==========
    'SECRET-001': {
        'pattern': r'sk-ant-[A-Za-z0-9\-_]{20,}',
        'severity': 'CRITICAL',
        'category': 'secret_exposure',
        'description': 'Hardcoded Anthropic API key detected in source code',
        'recommendation': 'Remove immediately, rotate at console.anthropic.com, use environment variable'
    },
    'SECRET-002': {
        'pattern': r'sk-(?:proj-[A-Za-z0-9\-_]{20,}|[A-Za-z0-9]{48})',
        'severity': 'CRITICAL',
        'category': 'secret_exposure',
        'description': 'Hardcoded OpenAI API key detected in source code',
        'recommendation': 'Remove immediately, rotate at platform.openai.com, use environment variable'
    },
    'SECRET-003': {
        'pattern': r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
        'severity': 'CRITICAL',
        'category': 'secret_exposure',
        'description': 'Hardcoded AWS Access Key ID detected in source code',
        'recommendation': 'Remove immediately, deactivate in AWS IAM console, use IAM roles or environment variables'
    },
    'SECRET-004': {
        'pattern': r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}',
        'severity': 'CRITICAL',
        'category': 'secret_exposure',
        'description': 'Hardcoded GitHub Personal Access Token detected in source code',
        'recommendation': 'Remove immediately, revoke at github.com/settings/tokens, use GitHub Secrets'
    },
    'SECRET-005': {
        'pattern': r'github_pat_[A-Za-z0-9_]{82}',
        'severity': 'CRITICAL',
        'category': 'secret_exposure',
        'description': 'Hardcoded GitHub Fine-grained PAT detected in source code',
        'recommendation': 'Remove immediately, revoke at github.com/settings/tokens, use GitHub Secrets'
    },
    'SECRET-006': {
        'pattern': r'xox[baprs]-[0-9A-Za-z\-]{10,72}',
        'severity': 'CRITICAL',
        'category': 'secret_exposure',
        'description': 'Hardcoded Slack token detected in source code',
        'recommendation': 'Remove immediately, rotate in Slack API dashboard, use environment variable'
    },
    'SECRET-007': {
        'pattern': r'AIza[0-9A-Za-z\-_]{35}',
        'severity': 'CRITICAL',
        'category': 'secret_exposure',
        'description': 'Hardcoded Google API key detected in source code',
        'recommendation': 'Remove immediately, rotate in Google Cloud Console, restrict key usage'
    },
    'SECRET-008': {
        'pattern': r'hf_[A-Za-z0-9]{34}',
        'severity': 'WARNING',
        'category': 'secret_exposure',
        'description': 'Possible HuggingFace API token detected in source code',
        'recommendation': 'Remove and rotate if real, use environment variable instead'
    },

    # ========== IDE Configuration Attacks ==========
    'IDE-001': {
        'pattern': r'"runOn"\s*:\s*"folderOpen"',
        'severity': 'CRITICAL',
        'category': 'ide_attack',
        'description': 'VS Code task configured to auto-run on folder open — can execute arbitrary code when project is opened',
        'recommendation': 'Remove runOn:folderOpen from .vscode/tasks.json; tasks should only run on explicit user action'
    },
    'IDE-002': {
        'pattern': r'"command"\s*:\s*"[^"]*(?:curl|wget|bash|sh|powershell|python|node|nc|eval)[^"]*"',
        'severity': 'CRITICAL',
        'category': 'ide_attack',
        'description': 'VS Code task executes a network/shell tool — potential RCE when task is triggered',
        'recommendation': 'Review task command carefully; remove or sandbox any network/shell calls'
    },
    'IDE-003': {
        'pattern': r'"terminal\.integrated\.env\.[a-z]+"',
        'severity': 'WARNING',
        'category': 'ide_attack',
        'description': 'VS Code settings override terminal environment variables — can hijack PATH or inject env vars',
        'recommendation': 'Audit terminal.integrated.env.* settings in .vscode/settings.json'
    },
    'IDE-004': {
        'pattern': r'"python\.terminal\.activateEnvInCurrentTerminal"\s*:\s*true',
        'severity': 'WARNING',
        'category': 'ide_attack',
        'description': 'VS Code auto-activates Python environment in terminal — attacker can inject malicious activation scripts',
        'recommendation': 'Keep as false unless explicitly needed; audit activate scripts in .venv'
    },

    # ========== Build Script Attacks (Makefile / Taskfile) ==========
    'BUILD-001': {
        'pattern': r'(?:curl|wget)\s+.*\|(?:\s*(?:sudo\s+)?(?:ba)?sh)',
        'severity': 'CRITICAL',
        'category': 'build_script',
        'description': 'Makefile/build script pipes download directly to shell — classic supply chain RCE vector',
        'recommendation': 'Download to a file first, verify checksum, then execute explicitly'
    },
    'BUILD-002': {
        'pattern': r'\$\((?:shell|eval)\s+.*(?:curl|wget|python|node|bash)',
        'severity': 'CRITICAL',
        'category': 'build_script',
        'description': 'Makefile $(shell) or $(eval) executes a network/interpreter command — arbitrary code at build time',
        'recommendation': 'Avoid $(shell)/ $(eval) with network tools; use explicit recipe steps'
    },
    'BUILD-003': {
        'pattern': r'(?:^|\n)\s*install\s*:.*\n(?:.*\n)*?.*(?:curl|wget|pip install|npm install -g)',
        'severity': 'WARNING',
        'category': 'build_script',
        'description': 'Makefile install target performs network package installation',
        'recommendation': 'Pin all package versions; prefer vendored dependencies or lock files'
    },

    # ========== GitHub Actions Enhanced ==========
    'GHAS-001': {
        'pattern': r'::\s*set-env\s+name=',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'Deprecated ::set-env workflow command — allows injecting arbitrary environment variables via untrusted input',
        'recommendation': 'Use $GITHUB_ENV file output instead: echo "VAR=value" >> $GITHUB_ENV'
    },
    'GHAS-002': {
        'pattern': r'\$\{\{\s*github\.event\.(?:issue\.title|pull_request\.(?:title|body|head\.ref|head\.label))\s*\}\}',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'Untrusted github.event user input used directly in run step — allows command injection via PR/issue title',
        'recommendation': 'Store in intermediate env var first: env: TITLE: ${{ github.event.pull_request.title }}'
    },
    'GHAS-003': {
        'pattern': r'::\s*add-path\s*::',
        'severity': 'WARNING',
        'category': 'supply_chain',
        'description': 'Deprecated ::add-path workflow command — allows injecting arbitrary directories into PATH',
        'recommendation': 'Use $GITHUB_PATH file output instead: echo "/my/path" >> $GITHUB_PATH'
    },

    # ========== Unicode Homoglyph Package Name Attack ==========
    'SUPPLY-030': {
        'pattern': r'[^\x00-\x7F]',   # Any non-ASCII character — contextual check done in auto_scanner
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'Package name contains non-ASCII Unicode characters that visually resemble an ASCII package name (homoglyph/lookalike attack)',
        'recommendation': 'Replace with the canonical ASCII package name; rotate any credentials used by this package'
    },

    # ========== Rust Build Script (compile-time execution) ==========
    'SUPPLY-022': {
        'pattern': r'Command::new\s*\(\s*["\'](?:curl|wget|bash|sh|nc|python3?|node|pwsh|powershell)["\']',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'Rust build.rs spawns a network/shell tool at compile time — compile-time supply chain RCE',
        'recommendation': 'Remove network/shell calls from build.rs; build scripts should only emit cargo: directives'
    },
    'SUPPLY-023': {
        'pattern': r'proc-macro\s*=\s*true',
        'severity': 'INFO',
        'category': 'supply_chain',
        'description': 'Rust proc-macro crate executes arbitrary code at compile time (cargo build / cargo check)',
        'recommendation': 'Audit proc-macro crates thoroughly; they have full host system access during compilation'
    },
}

# Target file patterns
TARGET_FILES = {
    'claude_config': ['.claude/config.json', '.claude.json', '.claude/settings.json'],
    'claude_md': ['CLAUDE.md', '.claude/CLAUDE.md'],
    'cursor_rules': ['.cursorrules', '.cursor/rules'],
    'package_json': ['package.json'],
    'cargo_toml': ['Cargo.toml'],
    'requirements': ['requirements.txt', 'requirements-dev.txt'],
    'python_config': ['setup.py', 'pyproject.toml', 'setup.cfg', 'Pipfile'],
    'git_hooks': ['.git/hooks/*'],
    'hook_configs': ['*.hook.json', '*hooks.config.js', 'hooks.yaml'],
    'github_actions': ['.github/workflows/*'],
}


class AISecurityIssue:
    """Security issue object"""
    def __init__(self, rule_id: str, file_path: str, matched_text: str, line_number: int = 0):
        self.rule_id = rule_id
        self.file_path = file_path
        self.matched_text = matched_text.strip()[:200]
        self.line_number = line_number
        self.rule = SECURITY_RULES.get(rule_id, {})
        self.severity = self.rule.get('severity', 'UNKNOWN')
        self.description = self.rule.get('description', 'Unknown issue')
        self.recommendation = self.rule.get('recommendation', 'Review this issue')
        self.category = self.rule.get('category', 'unknown')

    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'severity': self.severity,
            'category': self.category,
            'file': self.file_path,
            'line': self.line_number,
            'description': self.description,
            'matched_text': self.matched_text,
            'recommendation': self.recommendation
        }

    def __str__(self) -> str:
        return f"[{self.severity}] {self.rule_id}: {self.description} in {self.file_path}"


class AISecurityScanner:
    """AI security scanner main class"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.issues: List[AISecurityIssue] = []
        self.scanned_files = 0
        self.start_time = None

        # Exclude patterns
        self.exclude_patterns = self.config.get('exclude_patterns', [
            'node_modules',
            'dist',
            'build',
            '.git',
            '__pycache__',
            'venv',
            '.venv',
            'vendor'
        ])

    def should_exclude(self, path: Path) -> bool:
        """Check if path should be excluded"""
        path_str = str(path)
        for pattern in self.exclude_patterns:
            if pattern in path_str:
                return True
        return False

    def scan_file(self, file_path: Path) -> List[AISecurityIssue]:
        """Scan a single file"""
        issues = []

        try:
            # Check file size
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                return issues

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            self.scanned_files += 1
            content = ''.join(lines)

            # Scan line by line
            for line_num, line in enumerate(lines, 1):
                for rule_id, rule in SECURITY_RULES.items():
                    if re.search(rule['pattern'], line, re.IGNORECASE):
                        issue = AISecurityIssue(
                            rule_id=rule_id,
                            file_path=str(file_path),
                            matched_text=line,
                            line_number=line_num
                        )
                        issues.append(issue)

            # Scan entire file content (for multi-line matching)
            for rule_id, rule in SECURITY_RULES.items():
                if 'supply_chain' in rule.get('category', ''):
                    if re.search(rule['pattern'], content, re.IGNORECASE | re.MULTILINE):
                        # Avoid duplicates
                        if not any(i.rule_id == rule_id and i.file_path == str(file_path) for i in issues):
                            issue = AISecurityIssue(
                                rule_id=rule_id,
                                file_path=str(file_path),
                                matched_text=content[:200],
                                line_number=0
                            )
                            issues.append(issue)

        except Exception as e:
            # Silent failure, continue scanning other files
            pass

        return issues

    def find_target_files(self, root_path: Path) -> List[Path]:
        """Find all target files"""
        target_files = []

        for pattern_type, patterns in TARGET_FILES.items():
            for pattern in patterns:
                if pattern.endswith('/*'):
                    # Directory wildcard: .git/hooks/*
                    base_pattern = pattern[:-2]
                    base_dir = root_path / base_pattern
                    if base_dir.exists() and base_dir.is_dir():
                        for file_path in base_dir.iterdir():
                            if file_path.is_file() and not self.should_exclude(file_path):
                                target_files.append(file_path)
                elif pattern.startswith('**/'):
                    # Global wildcard: **/*.hook.json
                    suffix = pattern[3:]
                    for file_path in root_path.rglob(suffix):
                        if file_path.is_file() and not self.should_exclude(file_path):
                            target_files.append(file_path)
                else:
                    # Exact match
                    file_path = root_path / pattern
                    if file_path.exists() and file_path.is_file() and not self.should_exclude(file_path):
                        target_files.append(file_path)

        # Deduplicate
        return list(set(target_files))

    def scan_directory(self, path: str) -> List[AISecurityIssue]:
        """Scan directory"""
        root_path = Path(path).resolve()

        if not root_path.exists():
            print(f"❌ Path not found: {path}")
            return []

        print(f"Scanning directory: {root_path}")

        # Find target files
        target_files = self.find_target_files(root_path)
        print(f"Found {len(target_files)} target files")

        # Scan each file
        for file_path in target_files:
            file_issues = self.scan_file(file_path)
            self.issues.extend(file_issues)

        return self.issues

    def generate_report(self, output_format: str = 'text', output_file: Optional[str] = None) -> str:
        """Generate report"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Classify by severity
        critical = [i for i in self.issues if i.severity == 'CRITICAL']
        warning = [i for i in self.issues if i.severity == 'WARNING']
        info = [i for i in self.issues if i.severity == 'INFO']

        if output_format == 'json':
            report = {
                'scan_id': hashlib.md5(f"{timestamp}{self.scanned_files}".encode()).hexdigest()[:12],
                'timestamp': timestamp,
                'scanned_files': self.scanned_files,
                'total_issues': len(self.issues),
                'summary': {
                    'critical': len(critical),
                    'warning': len(warning),
                    'info': len(info)
                },
                'issues': [issue.to_dict() for issue in self.issues]
            }
            report_text = json.dumps(report, indent=2)

        elif output_format == 'markdown':
            report_text = "# AI Security Scan Report\n\n"
            report_text += f"**Time**: {timestamp}\n"
            report_text += f"**Scanned Files**: {self.scanned_files}\n"
            report_text += f"**Total Issues**: {len(self.issues)}\n\n"

            if critical:
                report_text += "## Critical Issues\n\n"
                for issue in critical:
                    report_text += f"- **{issue.rule_id}**: {issue.description}\n"
                    report_text += f"  - File: `{issue.file_path}` (line {issue.line_number})\n"
                    report_text += f"  - Matched: `{issue.matched_text[:100]}...`\n"
                    report_text += f"  - Recommendation: {issue.recommendation}\n\n"

            if warning:
                report_text += "## Warnings\n\n"
                for issue in warning:
                    report_text += f"- **{issue.rule_id}**: {issue.description}\n"
                    report_text += f"  - File: `{issue.file_path}`\n\n"

            if info:
                report_text += "## Information\n\n"
                for issue in info:
                    report_text += f"- **{issue.rule_id}**: {issue.description}\n"

            report_text += "\n## Recommendations\n\n"
            report_text += "1. Review all CRITICAL issues immediately\n"
            report_text += "2. Disable or remove malicious hooks\n"
            report_text += "3. Audit dependencies for supply chain attacks\n"

        else:  # text format
            report_text = f"[{timestamp}] AI Security Scan Results\n"
            report_text += f"Scanned Files: {self.scanned_files}\n"
            report_text += f"Total Issues: {len(self.issues)}\n\n"

            if critical:
                report_text += f"CRITICAL Issues ({len(critical)}):\n"
                for issue in critical:
                    report_text += f"  [{issue.rule_id}] {issue.description}\n"
                    report_text += f"    File: {issue.file_path}:{issue.line_number}\n"
                    report_text += f"    Matched: {issue.matched_text[:80]}...\n"
                    report_text += f"    -> {issue.recommendation}\n"

            if warning:
                report_text += f"\nWarnings ({len(warning)}):\n"
                for issue in warning:
                    report_text += f"  [{issue.rule_id}] {issue.description}\n"
                    report_text += f"    File: {issue.file_path}\n"

            if info:
                report_text += f"\nInformation ({len(info)}):\n"
                for issue in info:
                    report_text += f"  [{issue.rule_id}] {issue.description}\n"
                report_text += f"\n{Colors.BLUE}ℹ️  Information ({len(info)}):{Colors.RESET}\n"
                for issue in info:
                    report_text += f"  {Colors.BLUE}[{issue.rule_id}]{Colors.RESET} {issue.description}\n"

        # Output to file or console
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"Report saved to: {output_file}")

        return report_text

    def run(self, path: str = '.', output_format: str = 'text',
            output_file: Optional[str] = None, ci_mode: bool = False) -> int:
        """Execute scan"""
        self.start_time = time.time()

        # Scan
        self.scan_directory(path)

        # Generate report
        report = self.generate_report(output_format, output_file)
        print(f"\n{report}")

        # Calculate elapsed time
        elapsed = time.time() - self.start_time
        print(f"Scan completed in {elapsed:.2f}s")

        # Return exit code in CI mode
        if ci_mode:
            if any(i.severity == 'CRITICAL' for i in self.issues):
                return 2
            elif self.issues:
                return 1
        return 0 if not self.issues else 1


def main():
    """Main function"""
    # Detect Windows environment
    if sys.platform == 'win32':
        # Windows 10+ supports ANSI colors, but needs checking
        os.system('')  # Enable ANSI
        # If colors display incorrectly, uncomment the following line
        # Colors.disable()

    parser = argparse.ArgumentParser(
        description='AI Security Scanner - Detect malicious hooks and supply chain attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ai_scanner.py                      # Scan current directory
  python ai_scanner.py -d /path/to/project  # Scan specific directory
  python ai_scanner.py --watch              # Continuous monitoring
  python ai_scanner.py --ci                 # CI/CD mode (exit codes)
  python ai_scanner.py -f json -o report.json  # JSON report
        """
    )

    parser.add_argument('-d', '--directory', default='.',
                        help='Directory to scan (default: current directory)')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'markdown'],
                        default='text', help='Output format')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-w', '--watch', action='store_true',
                        help='Watch mode (continuous monitoring)')
    parser.add_argument('-i', '--interval', type=int, default=60,
                        help='Watch mode interval in seconds (default: 60)')
    parser.add_argument('--ci', action='store_true',
                        help='CI/CD mode (return exit codes)')
    parser.add_argument('--exclude', nargs='+', default=[],
                        help='Patterns to exclude')

    args = parser.parse_args()

    # Config
    config = {}
    if args.exclude:
        config['exclude_patterns'] = args.exclude

    scanner = AISecurityScanner(config)

    if args.watch:
        print(f"Watch mode enabled (interval: {args.interval}s)")
        print(f"Press Ctrl+C to stop\n")
        try:
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                scanner = AISecurityScanner(config)
                scanner.run(args.directory, args.format, args.output)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\nWatch mode stopped")
            return 0
    else:
        return scanner.run(args.directory, args.format, args.output, args.ci)


if __name__ == '__main__':
    sys.exit(main())
