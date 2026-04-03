# AI Security Scanner

AI Coding 时代的供应链与 AI hooks 安全扫描器
支持 **Claude Code** · **OpenClaw** · **CLI** · **CI/CD**

[主页](https://github.com/javamagong/ai-supply-chain-security) | [问题](https://github.com/javamagong/ai-supply-chain-security/issues) | [许可证: MIT](https://github.com/javamagong/ai-supply-chain-security/blob/main/LICENSE)

---

## 为什么选择这个工具?

AI 编程助手引入了传统扫描器无法检测的新攻击面:

- `.claude/settings.json` 中的恶意 hooks 会在每次提交时静默泄露源代码
- 假冒 MCP 服务器窃取 API 密钥
- 拼写抢注包如 `opeanai` 和 `litelm` 专门针对 AI 开发者
- `CLAUDE.md` 中的 Prompt 注入劫持 AI 助手行为

---

## 核心功能

### 1. AI 助手 Hooks 检测

扫描并修复:
- Claude Code `.claude/settings.json` 配置
- Cursor `.cursorrules` 文件
- 通用 `CLAUDE.md` 系统提示

### 2. MCP 服务器安全

检测:
- 未经验证的 MCP 服务器源
- 过度权限请求
- 可疑的环境变量访问

### 3. Prompt 注入检测

识别:
- 指令覆盖攻击
- 角色劫持尝试
- 虚假紧急指令
- 隐藏 Unicode 字符
- Base64 编码的隐藏指令

### 4. 供应链安全

**npm 包:**
- 已知恶意包 (colors, coa, rc 等)
- 危险生命周期脚本
- 依赖混淆攻击
- 拼写抢注

**Python 包:**
- setup.py 中的恶意代码
- pyproject.toml 可疑配置
- Git URL 依赖风险

**Rust 包:**
- build.rs 恶意代码
- 可疑的 cargo.toml

### 5. GitHub Actions 安全

- 未固定的 Action 版本
- 密钥泄露到日志
- 危险的触发器配置

---

## 快速开始

### OpenClaw 安装
```bash
openclaw skills install ai-supply-chain-security
```

### 手动安装
```bash
git clone https://github.com/javamagong/ai-supply-chain-security.git
cd ai-supply-chain-security
python ai_scanner.py --help
```

---

## 使用指南

### 基本扫描
```bash
# 扫描当前目录
python ai_scanner.py

# 扫描指定目录
python ai_scanner.py -d /path/to/project

# 完整扫描
python ai_scanner.py -d /path/to/project --full
```

### 自动发现扫描
```bash
# 扫描目录下的所有项目
python auto_scanner.py -d /path/to/projects

# 只显示严重问题
python auto_scanner.py -d /path/to/projects --severity critical
```

### 输出格式
```bash
# 文本输出 (默认)
python ai_scanner.py -f text

# JSON 输出
python ai_scanner.py -f json -o report.json

# Markdown 报告
python ai_scanner.py -f markdown -o report.md
```

---

## 配置

编辑 `config.yaml`:

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

---

## CI/CD 集成

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

---

## 要求

- Python 3.8+
- 依赖见 `requirements.txt`

---

## 许可证

MIT - 详见 LICENSE 文件

---

## 作者

JavaMaGong - https://github.com/javamagong
