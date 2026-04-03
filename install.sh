#!/usr/bin/env bash
# AI Security Scanner - One-Click Installer
# Supports: Claude Code, OpenClaw, CLI
#
# Usage:
#   git clone https://github.com/javamagong/ai-security-scanner.git
#   cd ai-security-scanner && bash install.sh
#
# Or if already cloned, just run:
#   bash install.sh

set -e

INSTALL_DIR="$HOME/.ai-security-scanner"
CLAUDE_COMMANDS_DIR="$HOME/.claude/commands"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔒 AI Security Scanner - Installer"
echo "===================================="

# ── Check Python ──────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo "❌ Python 3.8+ is required."
    echo "   Install: https://python.org/downloads/"
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]); then
    echo "❌ Python 3.8+ required (found $PY_VERSION)"
    exit 1
fi
echo "✅ Python $PY_VERSION"

# ── Install Python dependencies ───────────────────────────
echo "📦 Installing dependencies..."
$PYTHON -m pip install --quiet pyyaml colorama watchdog
echo "✅ Dependencies installed"

# ── Copy to install dir (if running from cloned repo) ─────
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    echo "📂 Installing to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR/." "$INSTALL_DIR/"
fi

# ── Claude Code: install slash command ────────────────────
if [ -d "$HOME/.claude" ]; then
    mkdir -p "$CLAUDE_COMMANDS_DIR"
    cp "$INSTALL_DIR/.claude/commands/security-scan.md" "$CLAUDE_COMMANDS_DIR/"
    echo "✅ Claude Code command installed → /security-scan"
else
    echo "ℹ️  Claude Code not detected — skipping /security-scan command"
    echo "   To install later: cp $INSTALL_DIR/.claude/commands/security-scan.md ~/.claude/commands/"
fi

# ── OpenClaw: show install command ────────────────────────
if command -v openclaw &>/dev/null; then
    echo ""
    echo "🦞 OpenClaw detected. Run to activate skill:"
    echo "   openclaw skills install $INSTALL_DIR"
else
    echo "ℹ️  OpenClaw not detected — CLI mode only"
fi

# ── Verify ────────────────────────────────────────────────
echo ""
echo "✅ Installation complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Usage:"
echo ""
if [ -d "$HOME/.claude" ]; then
echo "  Claude Code (restart required):"
echo "    /security-scan"
echo "    /security-scan /path/to/project"
echo ""
fi
echo "  CLI:"
echo "    $PYTHON $INSTALL_DIR/auto_scanner.py"
echo "    $PYTHON $INSTALL_DIR/auto_scanner.py -d /path/to/project"
echo "    $PYTHON $INSTALL_DIR/auto_scanner.py -d . --ci"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
