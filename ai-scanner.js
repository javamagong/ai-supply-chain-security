#!/usr/bin/env node
/**
 * AI Security Scanner - Node.js Version
 * 
 * Cross-platform Node.js implementation of the security scanner.
 * Use this if you don't have Python installed.
 * 
 * Usage:
 *   node ai-scanner.js -d /path/to/scan
 *   node ai-scanner.js --watch --interval 60
 *   node ai-scanner.js --ci -f json -o report.json
 * 
 * Requirements:
 *   - Node.js 14+
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// ANSI colors for output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m'
};

// Parse arguments
const args = process.argv.slice(2);
const options = {
    directory: '.',
    format: 'text',
    output: null,
    watch: false,
    interval: 60,
    ci: false,
    recursive: true
};

for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
        case '-d':
        case '--directory':
            options.directory = args[++i];
            break;
        case '-f':
        case '--format':
            options.format = args[++i];
            break;
        case '-o':
        case '--output':
            options.output = args[++i];
            break;
        case '-w':
        case '--watch':
            options.watch = true;
            break;
        case '-i':
        case '--interval':
            options.interval = parseInt(args[++i]);
            break;
        case '--ci':
            options.ci = true;
            break;
        case '--no-recursive':
            options.recursive = false;
            break;
        case '-h':
        case '--help':
            console.log(`
AI Security Scanner - Node.js Version

Usage:
  node ai-scanner.js [options]

Options:
  -d, --directory DIR    Directory to scan (default: current directory)
  -f, --format FORMAT    Output format: text or json (default: text)
  -o, --output FILE      Output file path
  -w, --watch           Watch mode (continuous monitoring)
  -i, --interval SECS   Watch interval in seconds (default: 60)
  --ci                  CI/CD mode (return exit codes)
  --no-recursive        Disable recursive scan
  -h, --help           Show this help message

Examples:
  node ai-scanner.js -d /path/to/project
  node ai-scanner.js --watch --interval 60
  node ai-scanner.js --ci -f json -o report.json
`);
            process.exit(0);
    }
}

// Detect Python
function detectPython() {
    const commands = ['python3', 'python'];
    for (const cmd of commands) {
        try {
            const result = require('child_process').spawnSync(cmd, ['--version']);
            if (result.status === 0) {
                return cmd;
            }
        } catch (e) {}
    }
    return null;
}

const pythonCmd = detectPython();
if (!pythonCmd) {
    console.error(`${colors.red}Error: Python 3 is required but not found.${colors.reset}`);
    console.error('Install it with: brew install python3 (macOS) or apt-get install python3 (Linux)');
    process.exit(1);
}

// Get script directory
const scriptDir = __dirname;
const scannerScript = path.join(scriptDir, 'ai-scanner.py');

// Build command
const pythonArgs = [scannerScript];
if (options.directory !== '.') {
    pythonArgs.push('-d', options.directory);
}
if (options.format !== 'text') {
    pythonArgs.push('-f', options.format);
}
if (options.output) {
    pythonArgs.push('-o', options.output);
}
if (options.watch) {
    pythonArgs.push('-w', '-i', options.interval.toString());
}
if (options.ci) {
    pythonArgs.push('--ci');
}
if (!options.recursive) {
    pythonArgs.push('--no-recursive');
}

// Run scanner
const child = spawn(pythonCmd, pythonArgs, {
    stdio: 'inherit',
    cwd: scriptDir
});

child.on('exit', (code) => {
    process.exit(code || 0);
});
