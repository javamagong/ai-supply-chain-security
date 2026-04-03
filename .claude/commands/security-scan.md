# AI Security Scanner

Scan a project directory for supply chain attacks, malicious hooks, MCP server risks, and prompt injection vulnerabilities.

## Usage

```
/security-scan [path]
```

- `[path]` — directory to scan (optional, defaults to current working directory)

---

Determine the scan target:
- If `$ARGUMENTS` is provided, use it as the target path
- Otherwise, use the current working directory

Find the scanner script by checking in order:
1. Same directory as this command file's project root (`auto_scanner.py`)
2. `~/.openclaw/skills/ai-security-scanner/auto_scanner.py`
3. `~/ai-security-scanner/auto_scanner.py`

Use the Bash tool to run:
```bash
python <scanner_path>/auto_scanner.py -d <target_path> -f json
```

Then present the results as follows:

**If CRITICAL issues found** — open with `⚠️ CRITICAL FINDINGS DETECTED` and list each one with:
- Rule ID and description
- Exact file path (and line number if available)
- Recommended remediation

**If only WARNING issues** — open with `⚠️ Warnings found` and group by category (supply_chain / hook_exfiltration / prompt_injection / obfuscation)

**If clean** — open with `✅ No security issues found in <path>`

Always end with a one-line summary: `Scanned X files — Critical: N, Warning: N, Info: N`
