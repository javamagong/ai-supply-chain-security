# AI Security Scanner - 安装指南

## 🎯 概述

**AI Security Scanner** 同时支持 **OpenClaw** 和 **Claude Code** 两个平台，提供跨平台的 AI 助手安全监控功能。

---

## 🦞 OpenClaw 安装

### 方式 1：从 ClawHub 安装（推荐）

```bash
openclaw skills install ai-security-scanner
```

### 方式 2：从本地目录安装

```bash
openclaw skills install /path/to/ai-security-scanner
```

### 方式 3：符号链接（开发时）

```bash
openclaw skills link ai-security-scanner /path/to/ai-security-scanner
```

安装后在对话中直接说「扫描 /path/to/project」即可触发扫描。

---

## 🤖 Claude Code 安装

### 方式 1：全局命令（推荐，任意项目可用）

```bash
# macOS / Linux
cp .claude/commands/security-scan.md ~/.claude/commands/

# Windows (PowerShell)
Copy-Item .claude\commands\security-scan.md ~\.claude\commands\
```

安装后在 Claude Code 中使用：
```
/security-scan                    # 扫描当前目录
/security-scan /path/to/project   # 扫描指定目录
```

### 方式 2：项目级命令（仅在本项目目录内可用）

无需额外操作，克隆本项目后在项目目录中打开 Claude Code，`/security-scan` 命令自动可用。

### 方式 3：手动触发（无需安装）

在 Claude Code 对话中直接输入：
```
用 python /path/to/auto_scanner.py -d . -f json 扫描当前项目，汇报安全问题
```

## 🔧 前置要求

- **Python**: 3.8+
- **OpenClaw**: 最新版本

安装前请确保 Python 已安装：

```bash
# 检查 Python 版本
python --version

# 如果没有安装，请先安装
# Windows: https://www.python.org/downloads/
# macOS: brew install python3
# Linux: sudo apt-get install python3
```

## 📁 安装后目录结构

安装成功后，Skill 会放在 OpenClaw 的 skills 目录下：

```
~/.openclaw/skills/
└── ai-security-scanner/
    ├── _meta.json
    ├── ai_scanner.py
    ├── auto_scanner.py
    ├── ai-scanner.py
    ├── config.yaml
    └── ...
```

## 🚀 使用方式

### 在 OpenClaw 对话中使用

安装后，你可以在 OpenClaw 对话中直接说：

```
扫描 D:\gitzone 项目
```

或者更具体的指令：

```
运行 ai-security-scanner 扫描 D:\projects
```

### 命令行使用

```bash
# 基本扫描
openclaw skills run ai-security-scanner --scan /path/to/project

# JSON 输出
openclaw skills run ai-security-scanner --scan /path --format json

# 持续监控
openclaw skills run ai-security-scanner --watch
```

## ⚙️ 配置

### 全局配置

在 OpenClaw 配置文件中添加：

```json
{
  "skills": {
    "ai-security-scanner": {
      "scanPaths": ["/path/to/projects"],
      "excludePatterns": ["**/node_modules/**"],
      "notifications": {
        "enabled": true,
        "webhook": "https://hooks.slack.com/xxx"
      }
    }
  }
}
```

### 项目级配置

在 `config.yaml` 中配置（如果 Skill 支持）：

```yaml
scan_paths:
  - ~/projects
  - ~/work

exclude_patterns:
  - "**/node_modules/**"
```

## 🔄 更新 Skill

```bash
# 更新到最新版本
openclaw skills update ai-security-scanner

# 查看当前版本
openclaw skills list | grep ai-security-scanner
```

## 🗑️ 卸载

```bash
openclaw skills uninstall ai-security-scanner
```

## ❓ 常见问题

### Q: 安装失败怎么办？

A: 检查：
1. Python 是否已安装（`python --version`）
2. OpenClaw 是否是最新版本（`openclaw --version`）
3. 网络连接是否正常

### Q: 如何调试问题？

A: 使用 verbose 模式：

```bash
openclaw skills install ai-security-scanner --verbose
```

### Q: Skill 不工作怎么办？

A: 
1. 检查 Python 版本（需要 3.8+）
2. 查看 OpenClaw 日志：`openclaw logs`
3. 重启 OpenClaw：`openclaw gateway restart`

## 📝 发布到 ClawHub

如果想将 Skill 发布到 ClawHub 供其他人使用：

### 1. 创建 GitHub 仓库

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/ai-security-scanner.git
git push -u origin main
```

### 2. 在 ClawHub 提交

访问 https://clawhub.com 提交你的 Skill。

### 3. 更新 _meta.json

确保 `_meta.json` 中的信息完整：

```json
{
  "ownerId": "your-clawhub-username",
  "slug": "ai-security-scanner",
  "version": "1.0.0",
  "author": "Your Name",
  "repository": "https://github.com/YOUR_USERNAME/ai-security-scanner"
}
```

---

## 📧 联系方式

- **作者**: JavaMaGong (AI Coding 辅助)
- **GitHub**: https://github.com/javamagong/ai-security-scanner
- **问题反馈**: https://github.com/javamagong/ai-security-scanner/issues

---

**版本**: 1.2.0  
**更新日期**: 2026-04-02  
**作者**: JavaMaGong (AI Coding 辅助)
