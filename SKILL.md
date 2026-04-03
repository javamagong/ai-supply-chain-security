# AI Security Scanner Skill

Cross-platform AI Coding security scanner for **OpenClaw** and **Claude Code**, detecting hooks configuration risks, MCP server attacks, prompt injection, and supply chain attacks (npm/PyPI/Rust).

## 📦 技能信息

```yaml
name: ai-supply-chain-security
version: 2.0.0
description: Cross-platform AI Coding security scanner - Detect hooks, MCP servers, prompt injection, and supply chain attacks
author: JavaMaGong
platforms: [Windows, macOS, Linux]
category: security
```

## 🚀 Installation

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

## 🎯 核心功能

### 1. AI 助手 Hooks 检测

| AI 助手 | 配置文件 | 检测内容 |
|---------|---------|----------|
| Claude Code | `.claude/settings.json` | hooks、MCP servers、permissions |
| Cursor | `.cursorrules` | Prompt 注入 |
| 通用 | `CLAUDE.md` | Prompt 注入攻击 |

### 2. 供应链投毒检测

#### npm/Node.js
- ✅ `postinstall`、`preinstall`、`prepare` 危险脚本
- ✅ 已知恶意包（event-stream、colors、crossenv 等 20+ 个包）
- ✅ 拼写错误攻击（axios/axois、lodash/ladash 等）

#### Python
- ✅ `requirements.txt` — git URL 依赖、非官方 PyPI 索引、版本未锁定、直接 URL 安装
- ✅ `Pipfile` — git 依赖、通配符版本 `"*"`、拼写错误包名
- ✅ `pyproject.toml` — PEP 621 / Poetry / PDM 依赖解析
- ✅ `setup.py` — cmdclass 钩子、os.system/subprocess、网络请求

**AI 生态专项保护**（针对 API Key 窃取攻击）：

| 官方包 | 检测的恶意变体 |
|--------|--------------|
| `openai` | opeanai, open-ai, openaii |
| `anthropic` | antrhopic, anthropicc, anthopic |
| `litellm` | litelm, lite-llm, litelllm |
| `langchain` | langcain, lang-chain, langchian |
| `transformers` | tranformers, trannsformers |

#### Rust
- ✅ `Cargo.toml` 未固定版本依赖
- ✅ git URL 依赖

### 3. MCP 服务器安全检测

检测 `.claude/settings.json` 中的 `mcpServers` 配置：

- ✅ 外部 URL 连接检测（非 localhost 地址）
- ✅ 可疑命令注入检测
- ✅ 敏感环境变量透传检测（API_KEY、TOKEN 等）

### 4. Prompt Injection Detection

Detects suspicious patterns in `CLAUDE.md` and `.cursorrules`:

- ✅ Instruction override patterns (e.g., phrases attempting to clear previous context)
- ✅ Role hijacking attempts (e.g., claims to change AI identity)
- ✅ Fake urgency commands (e.g., URGENT override requests)
- ✅ Hidden Unicode characters (zero-width chars like U+200B, U+200C, U+200D)
- ✅ Base64 encoded hidden instructions

### 5. GitHub Actions 安全检测

- ✅ 未固定版本的 Action（`@main`、`@master`、`@HEAD`）
- ✅ Secrets 泄露到日志（`echo ${{ secrets.KEY }}`）
- ✅ `pull_request_target` 危险触发器

### 6. 代码混淆检测

- ✅ OBFUSC-001: 十六进制编码字符串（`\x63\x75\x72\x6c`）
- ✅ OBFUSC-002: `exec(base64.b64decode(...))`
- ✅ OBFUSC-003: `__import__('subprocess')` 动态导入
- ✅ OBFUSC-004: `chr()` 逐字符构建字符串
- ✅ OBFUSC-005: `exec(compile(source, ...))`
- ✅ OBFUSC-006: `exec(bytes.fromhex(...))`

## 🚀 安装方式

### 方式 1: OpenClaw（推荐）

```bash
openclaw skills install ai-security-scanner
```

### 方式 2: Claude Code

```bash
# macOS / Linux
cp .claude/commands/security-scan.md ~/.claude/commands/

# Windows
Copy-Item .claude\commands\security-scan.md ~\.claude\commands\
```

### 方式 3: 一键安装（自动配置两个平台）

```bash
git clone https://github.com/javamagong/ai-security-scanner.git ~/.ai-security-scanner
bash ~/.ai-security-scanner/install.sh
```

### 方式 4: 独立使用

```bash
pip install pyyaml colorama watchdog
python auto_scanner.py -d /path/to/project
```

## 💡 使用示例

### 基础扫描

```bash
# 当前目录
python ai-scanner.py

# 指定目录
python ai-scanner.py -d /path/to/project

# 非递归（只扫顶层）
python ai-scanner.py -d . --no-recursive
```

### 输出格式

```bash
# 文本输出（默认）
python ai-scanner.py

# JSON 输出
python ai-scanner.py -f json -o report.json

# CI/CD 模式（有问题返回错误码）
python ai-scanner.py --ci
```

### 持续监控

```bash
# 每 60 秒扫描一次
python ai-scanner.py --watch --interval 60
```

## 🔍 检测规则详解

### 高危规则（Critical）

| ID | 规则 | 说明 | 影响的文件 |
|----|------|------|-----------|
| HOOK-001 | `curl.*\|.*bash` | 下载并执行远程脚本 | package.json, settings.json |
| HOOK-002 | `wget.*\|.*sh` | 下载并执行远程脚本 | package.json, settings.json |
| HOOK-003 | `rm -rf` | 递归删除文件 | package.json, hooks |
| HOOK-004 | `chmod 777` | 设置完全权限 | hooks |
| HOOK-005 | `eval()` / `exec()` | 执行动态代码 | setup.py, hooks |
| HOOK-006 | `base64.*decode` | 解码执行隐蔽代码 | hooks |
| SUPPLY-001 | npm postinstall 危险命令 | 供应链投毒 | package.json |
| SUPPLY-002 | Python git URL 依赖 | 外部代码注入 | requirements.txt |
| SUPPLY-003 | 非官方 PyPI 索引 | 依赖混淆攻击 | requirements.txt |
| MCP-001 | MCP 服务器外部 URL | 数据外泄 | settings.json |
| MCP-002 | MCP 命令注入 | 远程代码执行 | settings.json |
| PROMPT-001 | 指令覆盖攻击 | Prompt 注入 | CLAUDE.md |

### 中危规则（Warning）

| ID | 规则 | 说明 |
|----|------|------|
| HOOK-010 | `python -c` | 执行 Python 代码 |
| HOOK-011 | `node -e` | 执行 Node.js 代码 |
| HOOK-012 | `powershell` | 执行 PowerShell |
| HOOK-013 | `nc.*-e` | 网络反弹 shell |
| SUPPLY-010 | 版本未锁定 | 可被版本劫持 |
| SUPPLY-011 | setup.py cmdclass | 自定义安装命令 |
| MCP-003 | MCP 凭证透传 | 敏感信息泄露 |

### 低危规则（Info）

| ID | 规则 | 说明 |
|----|------|------|
| HOOK-020 | `npm install -g` | 全局安装包 |
| HOOK-021 | `pip install` | 安装 Python 包 |
| HOOK-022 | `cargo install` | 安装 Rust 工具 |

## 🛡️ 已知恶意包名单

### npm 生态（20+ 个）

| 包名 | 事件 | 危害 |
|------|------|------|
| event-stream | 2018 | 窃取比特币钱包私钥 |
| flatmap-stream | 2018 | 植入挖矿代码 |
| crossenv | 2021 | 窃取环境变量凭证 |
| ua-parser-js | 2021 | 窃取浏览器密码 |
| colors | 2022 | 破坏生产环境（打印乱码） |
| node-ipc | 2022 | 特定地区删除文件 |
| coa / rc | 2021 | 凭证窃取 |
| lofygang | 2022 | Discord token 窃取 |

### PyPI 生态（10+ 个）

| 包名 | 类型 | 危害 |
|------|------|------|
| colourama | 拼写错误 | 窃取凭证 |
| python3-dateutil | 拼写错误 | 植入后门 |
| jeIlyfish | Unicode 混淆 | 窃取 SSH 密钥 |
| python-binance | 拼写错误 | 窃取加密资产 |
| ctx | 包劫持 | 窃取环境变量 |
| openai-api | 拼写错误 | 窃取 OpenAI API Key |
| opeanai | 拼写错误 | 窃取 OpenAI API Key |

### AI 生态拼写错误保护

| 官方包 | 恶意变体 |
|--------|----------|
| openai | opeanai, open-ai, openaii |
| anthropic | antrhopic, anthropicc, anthopic |
| litellm | litelm, lite-llm, litelllm |
| langchain | langcain, lang-chain, langchian |
| transformers | tranformers, trannsformers |
| huggingface-hub | hugginface-hub, huggingfce-hub |
| chromadb | chroma-db, cromadb, chromaddb |

## 📊 报告格式

### 文本报告

```
============================================================
AI Security Scanner v2.0 - Comprehensive Report
============================================================

[Projects Found]: 1
  - /path/to/project
    Types: npm, python

[AI Config Security]: 2 issues
  [CRITICAL] MCP 服务器连接外部地址: evil-mcp
    File: /path/to/.claude/settings.json
    Fix: 验证 MCP 服务器是否可信

[Dependency Issues]: 3 issues
  [CRITICAL] Python 依赖通过 git URL 安装
    File: /path/to/requirements.txt:5
    Fix: 改用 PyPI 固定版本

[Summary]
  Total issues:     5
  Critical:         2
  Warning:          3
============================================================
```

### JSON 报告

```json
{
  "projects_found": ["/path/to/project"],
  "project_types": {"/path/to/project": ["npm", "python"]},
  "dependency_issues": [...],
  "ai_config_issues": [...],
  "file_changes": {...},
  "security_issues": {
    "critical": 2,
    "warning": 3,
    "total": 5,
    "details": [...]
  }
}
```

## ⚙️ 配置选项

### config.yaml

```yaml
# 扫描路径
scan_paths:
  - ~/projects
  - ~/work

# 排除模式
exclude_patterns:
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.git/**"

# 启用的规则
rules:
  enabled:
    - HOOK-001
    - HOOK-002
    - SUPPLY-001
    - SUPPLY-002
    - MCP-001
    - PROMPT-001

# 报告设置
report:
  format: markdown
  output_dir: ./reports
  retention_days: 30

# CI/CD 设置
ci:
  fail_on_critical: true
  fail_on_warning: false
```

## 📈 CI/CD 集成

### GitHub Actions

```yaml
name: AI Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: AI Security Scan
        run: |
          pip install -r requirements.txt
          python ai-scanner.py --ci -f json -o security-report.json
          
      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: security-report.json
```

## 🧪 测试

```bash
# 运行测试
pytest tests/ -v

# 扫描示例目录
python ai-scanner.py -d examples --no-recursive
```

## 📚 相关资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SLSA Framework](https://slsa.dev/)
- [npm Security Best Practices](https://docs.npmjs.com/cli/v9/using-npm/security)
- [PyPI Security](https://pypi.org/security/)
- [Socket Security Blog](https://socket.dev/blog/)

## 🤝 贡献指南

1. Fork 仓库
2. 创建功能分支：`git checkout -b feature/new-detection`
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

### 添加新的恶意包

在 `auto_scanner.py` 的 `MALICIOUS_PACKAGES` 字典中添加：

```python
'<package-name>': {
    'type': 'supply_chain',
    'severity': 'CRITICAL',
    'ecosystem': 'npm',  # 或 'pypi'
    'reason': '事件描述',
    'damage': '危害',
    'remediation': '处理建议'
}
```

## 📄 许可证

MIT License - 详见 LICENSE 文件

---

**版本**: 2.0.0  
**更新日期**: 2026-04-02  
**作者**: JavaMaGong (AI Coding 辅助)
