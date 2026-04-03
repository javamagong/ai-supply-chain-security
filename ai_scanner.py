#!/usr/bin/env python3
"""
AI Security Scanner - Cross-platform
支持：Windows, macOS, Linux
检测 AI 助手 hooks 配置风险和供应链投毒

Usage:
    python ai_scanner.py                    # 扫描当前目录
    python ai_scanner.py -d /path/to/dir   # 扫描指定目录
    python ai_scanner.py --watch           # 持续监控
    python ai_scanner.py --ci              # CI/CD 模式
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

# 跨平台颜色支持
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
        """Windows 或不支持颜色的终端"""
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.MAGENTA = ''
        cls.CYAN = ''
        cls.RESET = ''
        cls.BOLD = ''

# 检测规则库
SECURITY_RULES = {
    # 高危规则 - 远程代码执行
    'HOOK-001': {
        'pattern': r'curl\s+[^|]+\|\s*(bash|sh|zsh|dash)',
        'severity': 'CRITICAL',
        'category': 'remote_code_execution',
        'description': '下载并执行远程脚本 (curl | bash)',
        'recommendation': '移除此 hooks 或使用固定版本的脚本'
    },
    'HOOK-002': {
        'pattern': r'wget\s+[^|]+\|\s*(bash|sh|zsh|dash)',
        'severity': 'CRITICAL',
        'category': 'remote_code_execution',
        'description': '下载并执行远程脚本 (wget | bash)',
        'recommendation': '移除此 hooks 或先下载后审计再执行'
    },
    'HOOK-003': {
        'pattern': r'bash\s+-c\s+[\'"]?\s*(curl|wget)',
        'severity': 'CRITICAL',
        'category': 'remote_code_execution',
        'description': '通过 bash -c 执行远程脚本',
        'recommendation': '避免使用 bash -c 执行远程代码'
    },
    
    # 高危规则 - 破坏性命令
    'HOOK-004': {
        'pattern': r'rm\s+(-[rf]+\s+)?(/\w+|~|\*|\.\.)',
        'severity': 'CRITICAL',
        'category': 'destructive_command',
        'description': '递归删除命令，可能删除重要文件',
        'recommendation': '审查删除路径，避免使用 rm -rf'
    },
    'HOOK-005': {
        'pattern': r'del\s+/[sqm]?\s+\S+',
        'severity': 'CRITICAL',
        'category': 'destructive_command',
        'description': 'Windows 删除命令',
        'recommendation': '审查删除操作'
    },
    'HOOK-006': {
        'pattern': r'format\s+[a-zA-Z]:',
        'severity': 'CRITICAL',
        'category': 'destructive_command',
        'description': '格式化磁盘命令',
        'recommendation': '立即移除，极度危险'
    },
    
    # 高危规则 - 权限提升
    'HOOK-007': {
        'pattern': r'chmod\s+777',
        'severity': 'CRITICAL',
        'category': 'privilege_escalation',
        'description': '设置文件为完全可执行权限',
        'recommendation': '使用最小权限原则'
    },
    'HOOK-008': {
        'pattern': r'sudo\s+(rm|chmod|chown)',
        'severity': 'CRITICAL',
        'category': 'privilege_escalation',
        'description': '使用 root 权限执行危险命令',
        'recommendation': '避免使用 sudo 执行危险命令'
    },
    
    # 中危规则 - 代码执行
    'HOOK-010': {
        'pattern': r'eval\s*\(',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': '使用 eval 执行动态代码',
        'recommendation': '审查 eval 内容，避免执行用户输入'
    },
    'HOOK-011': {
        'pattern': r'python\s+(-c|--command)\s+[\'"]',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': '执行 Python 代码',
        'recommendation': '审查 Python 代码内容'
    },
    'HOOK-012': {
        'pattern': r'node\s+(-e|--eval)\s+[\'"]',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': '执行 Node.js 代码',
        'recommendation': '审查 JavaScript 代码内容'
    },
    'HOOK-013': {
        'pattern': r'powershell(?:\.exe)?\s+(?:-c|-command|-EncodedCommand|EncodedCommand)',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': '执行 PowerShell 命令',
        'recommendation': '审查 PowerShell 命令内容'
    },
    'HOOK-014': {
        'pattern': r'base64\s+(-d|--decode)',
        'severity': 'WARNING',
        'category': 'code_execution',
        'description': '解码 base64 编码的内容',
        'recommendation': '审查解码后的内容'
    },
    
    # 中危规则 - 网络操作
    'HOOK-020': {
        'pattern': r'nc\s+(-e|--exec)',
        'severity': 'WARNING',
        'category': 'network',
        'description': 'netcat 反弹 shell',
        'recommendation': '高度可疑，可能是后门'
    },
    'HOOK-021': {
        'pattern': r'bash\s+-i\s+>&\s+/dev/tcp',
        'severity': 'WARNING',
        'category': 'network',
        'description': 'Bash 反弹 shell',
        'recommendation': '高度可疑，立即审查'
    },
    'HOOK-022': {
        'pattern': r'(curl|wget)\s+.*-o\s+\S*\.(sh|py|js|exe|bin)',
        'severity': 'WARNING',
        'category': 'network',
        'description': '下载可执行文件',
        'recommendation': '审查下载的文件来源'
    },
    
    # 低危规则 - 包管理
    'HOOK-030': {
        'pattern': r'npm\s+install\s+(-g|--global)',
        'severity': 'INFO',
        'category': 'package_manager',
        'description': '全局安装 npm 包',
        'recommendation': '审查安装的包'
    },
    'HOOK-031': {
        'pattern': r'pip\s+install\s+(-U|--upgrade|--user)',
        'severity': 'INFO',
        'category': 'package_manager',
        'description': '安装/升级 Python 包',
        'recommendation': '审查安装的包'
    },
    'HOOK-032': {
        'pattern': r'cargo\s+install',
        'severity': 'INFO',
        'category': 'package_manager',
        'description': '安装 Rust 包',
        'recommendation': '审查安装的包'
    },
    
    # 供应链投毒检测（JSON 格式：key 和 value 均被双引号包裹）
    'SUPPLY-001': {
        'pattern': r'postinstall["\']?\s*:\s*["\']?(curl|wget|bash|sh|rm|del)',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'npm package.json postinstall 脚本包含危险命令',
        'recommendation': '审查此依赖包，可能是恶意包'
    },
    'SUPPLY-002': {
        'pattern': r'preinstall["\']?\s*:\s*["\']?(curl|wget|bash|sh|rm|del)',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'npm package.json preinstall 脚本包含危险命令',
        'recommendation': '审查此依赖包'
    },
    'SUPPLY-003': {
        'pattern': r'prepare["\']?\s*:\s*["\']?(curl|wget|bash|sh)',
        'severity': 'WARNING',
        'category': 'supply_chain',
        'description': 'npm package.json prepare 脚本包含可疑命令',
        'recommendation': '审查此依赖包'
    },

    # ========== Claude Code / AI 助手 Hooks 检测 ==========
    'CLAUDE-001': {
        'pattern': r'"mcpServers"\s*:\s*\{[^}]*"(?:url|command)"\s*:\s*"[^"]*https?://',
        'severity': 'WARNING',
        'category': 'mcp_server',
        'description': 'MCP 服务器配置包含外部 URL，可能存在数据外泄风险',
        'recommendation': '验证 MCP 服务器 URL 是否可信，确认为官方或内部服务'
    },
    'CLAUDE-002': {
        'pattern': r'(?:ignore\s+(?:all\s+)?previous|disregard\s+(?:all\s+)?above|override\s+(?:all\s+)?instructions|you\s+are\s+now|forget\s+(?:all\s+)?(?:prior|previous)|new\s+system\s+prompt|IMPORTANT:\s*(?:ignore|override|disregard))',
        'severity': 'CRITICAL',
        'category': 'prompt_injection',
        'description': '检测到 Prompt 注入攻击模式，试图覆盖 AI 助手指令',
        'recommendation': '立即审查文件，移除恶意注入内容'
    },
    'CLAUDE-003': {
        'pattern': r'"(?:command|hooks)"[^}]*(?:curl|wget|nc|bash\s+-[ic])\s+.*https?://',
        'severity': 'CRITICAL',
        'category': 'hook_exfiltration',
        'description': 'Hooks 命令调用外部 URL，可能外泄源码或凭证',
        'recommendation': '审查 hook 命令，移除可疑的网络调用'
    },
    'CLAUDE-004': {
        'pattern': r'\$\w*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|ANTHROPIC|OPENAI|AWS|AZURE|GCP|GITHUB|GITLAB|SLACK|DISCORD)\w*',
        'severity': 'CRITICAL',
        'category': 'hook_exfiltration',
        'description': 'Hooks 命令引用敏感环境变量，可能窃取凭证',
        'recommendation': '审查 hook 命令，确保不会泄露环境变量'
    },
    'CLAUDE-005': {
        'pattern': r'[\u200b\u200c\u200d\u2060\ufeff\u00ad]',
        'severity': 'WARNING',
        'category': 'prompt_injection',
        'description': '检测到零宽字符/隐藏 Unicode，可能用于隐藏恶意指令',
        'recommendation': '审查文件，移除不可见字符'
    },

    # ========== 供应链投毒 - Python 生态 ==========
    'SUPPLY-010': {
        'pattern': r'(?:^|\s)[\w-]+\s*@\s*git\+https?://|^-e\s+git\+https?://|^git\+https?://',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'Python 依赖通过 git URL 安装，可能指向恶意仓库',
        'recommendation': '验证 git URL 是否为官方仓库，改用 PyPI 固定版本'
    },
    'SUPPLY-011': {
        'pattern': r'--?(?:index-url|extra-index-url)\s+https?://(?!(?:pypi\.org|files\.pythonhosted\.org))',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': '使用非官方 PyPI 索引，可能导致依赖混淆攻击',
        'recommendation': '确认索引 URL 是否为可信的私有仓库'
    },
    'SUPPLY-012': {
        'pattern': r'cmdclass\s*[=:]\s*\{',
        'severity': 'WARNING',
        'category': 'supply_chain',
        'description': 'setup.py 使用自定义 cmdclass，可在安装时执行任意代码',
        'recommendation': '审查 cmdclass 实现，确认无恶意行为'
    },
    'SUPPLY-013': {
        'pattern': r'(?:os\.system|subprocess\.(?:call|run|Popen)|exec|eval)\s*\(',
        'severity': 'WARNING',
        'category': 'supply_chain',
        'description': 'setup.py/构建脚本中执行系统命令',
        'recommendation': '审查命令内容，确认无恶意行为'
    },

    # ========== 供应链投毒 - GitHub Actions ==========
    'SUPPLY-020': {
        'pattern': r'uses:\s+[\w-]+/[\w-]+@(?:main|master|dev|develop|HEAD)\b',
        'severity': 'CRITICAL',
        'category': 'supply_chain',
        'description': 'GitHub Actions 引用未固定分支，可被投毒替换',
        'recommendation': '使用 commit SHA 或固定版本标签（如 @v3.1.0）'
    },
    'SUPPLY-021': {
        'pattern': r'uses:\s+[\w-]+/[\w-]+@[a-f0-9]{7}(?![a-f0-9])',
        'severity': 'INFO',
        'category': 'supply_chain',
        'description': 'GitHub Actions 使用短 SHA 引用，存在碰撞风险',
        'recommendation': '使用完整 40 字符 commit SHA'
    },

    # ========== 代码混淆检测 ==========
    'OBFUSC-001': {
        'pattern': r'(?:\\x[0-9a-fA-F]{2}){4,}',
        'severity': 'WARNING',
        'category': 'obfuscation',
        'description': '检测到大量十六进制编码字符串，可能隐藏恶意命令',
        'recommendation': '解码并审查实际内容'
    },
    'OBFUSC-002': {
        'pattern': r'(?:exec|eval)\s*\([^)]*(?:base64|b64decode|b64_decode|codecs\.decode|bytes\.fromhex)',
        'severity': 'CRITICAL',
        'category': 'obfuscation',
        'description': '执行编码/解码后的代码，高度可疑的恶意行为',
        'recommendation': '立即解码审查，极可能是恶意代码'
    },
    'OBFUSC-003': {
        'pattern': r'__import__\s*\(\s*[\'"](?:os|subprocess|shutil|socket|http|urllib|requests|ctypes)[\'"]',
        'severity': 'CRITICAL',
        'category': 'obfuscation',
        'description': '使用 __import__ 动态导入敏感模块，规避静态分析',
        'recommendation': '审查代码意图，改用显式 import'
    },
    'OBFUSC-004': {
        'pattern': r'(?:chr\s*\(\s*\d+\s*\)\s*\+?\s*){4,}',
        'severity': 'WARNING',
        'category': 'obfuscation',
        'description': '使用 chr() 逐字符构建字符串，隐藏真实内容',
        'recommendation': '还原并审查构建的字符串'
    },
    'OBFUSC-005': {
        'pattern': r'(?:exec|eval)\s*\(\s*compile\s*\(',
        'severity': 'CRITICAL',
        'category': 'obfuscation',
        'description': '使用 compile() + exec/eval 执行动态代码',
        'recommendation': '审查编译的代码内容'
    },
    'OBFUSC-006': {
        'pattern': r'exec\s*\(\s*(?:bytes\.fromhex|bytearray\.fromhex)\s*\(',
        'severity': 'CRITICAL',
        'category': 'obfuscation',
        'description': '从十六进制字节序列执行代码',
        'recommendation': '解码并审查实际代码'
    },
}

# 目标文件模式
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
    """安全问题对象"""
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
    """AI 安全扫描器主类"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.issues: List[AISecurityIssue] = []
        self.scanned_files = 0
        self.start_time = None
        
        # 排除模式
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
        """检查路径是否应该排除"""
        path_str = str(path)
        for pattern in self.exclude_patterns:
            if pattern in path_str:
                return True
        return False
    
    def scan_file(self, file_path: Path) -> List[AISecurityIssue]:
        """扫描单个文件"""
        issues = []
        
        try:
            # 检查文件大小
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                return issues
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            self.scanned_files += 1
            content = ''.join(lines)
            
            # 逐行扫描
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
            
            # 对整个文件内容的扫描（用于多行匹配）
            for rule_id, rule in SECURITY_RULES.items():
                if 'supply_chain' in rule.get('category', ''):
                    if re.search(rule['pattern'], content, re.IGNORECASE | re.MULTILINE):
                        # 避免重复
                        if not any(i.rule_id == rule_id and i.file_path == str(file_path) for i in issues):
                            issue = AISecurityIssue(
                                rule_id=rule_id,
                                file_path=str(file_path),
                                matched_text=content[:200],
                                line_number=0
                            )
                            issues.append(issue)
        
        except Exception as e:
            # 静默失败，继续扫描其他文件
            pass
        
        return issues
    
    def find_target_files(self, root_path: Path) -> List[Path]:
        """查找所有目标文件"""
        target_files = []
        
        for pattern_type, patterns in TARGET_FILES.items():
            for pattern in patterns:
                if pattern.endswith('/*'):
                    # 目录通配符：.git/hooks/*
                    base_pattern = pattern[:-2]
                    base_dir = root_path / base_pattern
                    if base_dir.exists() and base_dir.is_dir():
                        for file_path in base_dir.iterdir():
                            if file_path.is_file() and not self.should_exclude(file_path):
                                target_files.append(file_path)
                elif pattern.startswith('**/'):
                    # 全局通配符：**/*.hook.json
                    suffix = pattern[3:]
                    for file_path in root_path.rglob(suffix):
                        if file_path.is_file() and not self.should_exclude(file_path):
                            target_files.append(file_path)
                else:
                    # 精确匹配
                    file_path = root_path / pattern
                    if file_path.exists() and file_path.is_file() and not self.should_exclude(file_path):
                        target_files.append(file_path)
        
        # 去重
        return list(set(target_files))
    
    def scan_directory(self, path: str) -> List[AISecurityIssue]:
        """扫描目录"""
        root_path = Path(path).resolve()
        
        if not root_path.exists():
            print(f"❌ Path not found: {path}")
            return []
        
        print(f"Scanning directory: {root_path}")
        
        # 查找目标文件
        target_files = self.find_target_files(root_path)
        print(f"Found {len(target_files)} target files")
        
        # 扫描每个文件
        for file_path in target_files:
            file_issues = self.scan_file(file_path)
            self.issues.extend(file_issues)
        
        return self.issues
    
    def generate_report(self, output_format: str = 'text', output_file: Optional[str] = None) -> str:
        """生成报告"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 按严重程度分类
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
        
        # 输出到文件或控制台
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"Report saved to: {output_file}")
        
        return report_text
    
    def run(self, path: str = '.', output_format: str = 'text', 
            output_file: Optional[str] = None, ci_mode: bool = False) -> int:
        """执行扫描"""
        self.start_time = time.time()
        
        # 扫描
        self.scan_directory(path)
        
        # 生成报告
        report = self.generate_report(output_format, output_file)
        print(f"\n{report}")
        
        # 计算耗时
        elapsed = time.time() - self.start_time
        print(f"Scan completed in {elapsed:.2f}s")
        
        # CI 模式下返回退出码
        if ci_mode:
            if any(i.severity == 'CRITICAL' for i in self.issues):
                return 2
            elif self.issues:
                return 1
        return 0 if not self.issues else 1


def main():
    """主函数"""
    # 检测 Windows 环境
    if sys.platform == 'win32':
        # Windows 10+ 支持 ANSI 颜色，但需要检查
        os.system('')  # 启用 ANSI
        # 如果颜色显示异常，取消下面这行的注释
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
    
    # 配置
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
