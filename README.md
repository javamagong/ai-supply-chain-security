# AI Security Scanner

跨平台 AI 助手安全监控技能，检测 Claude Code、Cursor 等 AI 助手的 hooks 配置风险和供应链投毒攻击。

## Features

- **跨平台支持**: Windows, macOS, Linux
- **多 AI 助手检测**: Claude Code, Cursor, 自定义 hooks
- **供应链投毒检测**: npm, pip, Cargo 依赖包检查
- **多种运行模式**: 单次扫描、持续监控、CI/CD 集成、定时任务

## Installation

### Option 1: As LobsterAI Skill

```bash
openclaw skills install ai-security-scanner
```

### Option 2: Standalone

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/ai-security-scanner.git
cd ai-security-scanner

# Run
python ai-scanner.py -d /path/to/project
```

## Usage

```bash
# Scan current directory
python ai-scanner.py

# Scan specific directory
python ai-scanner.py -d /path/to/project

# JSON output
python ai-scanner.py -f json -o report.json

# Watch mode (continuous monitoring)
python ai-scanner.py --watch --interval 60

# CI/CD mode
python ai-scanner.py --ci
```

## Shell Wrapper (macOS/Linux)

```bash
chmod +x ai-scanner.sh
./ai-scanner.sh -d /path/to/project
```

## Node.js Version

```bash
node ai-scanner.js -d /path/to/project
```

## Requirements

- Python 3.8+ (or Node.js 14+)

## License

MIT
