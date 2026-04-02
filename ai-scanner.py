#!/usr/bin/env python3
"""
AI Security Scanner - Cross-platform Security Scanner
Cross-platform: Windows, macOS, Linux

Usage:
    python ai-scanner.py -d /path/to/scan
    python ai-scanner.py --watch --interval 60
    python ai-scanner.py --ci -f json -o report.json
"""

import sys
import os
from pathlib import Path

# Add the skill directory to Python path
SKILL_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SKILL_DIR))

from auto_scanner import AutoSecurityScanner
import json
import argparse


def main():
    parser = argparse.ArgumentParser(
        description='AI Security Scanner - Cross-platform Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ai-scanner.py                         # Scan current directory
  python ai-scanner.py -d /path/to/project    # Scan specific directory
  python ai-scanner.py --watch                 # Watch mode
  python ai-scanner.py --ci                    # CI/CD mode
  python ai-scanner.py -f json -o report.json # JSON output
        """
    )
    
    parser.add_argument('-d', '--directory', default='.', 
                        help='Directory to scan (default: current directory)')
    parser.add_argument('-f', '--format', choices=['text', 'json'], 
                        default='text', help='Output format')
    parser.add_argument('-o', '--output', 
                        help='Output file path')
    parser.add_argument('-w', '--watch', action='store_true', 
                        help='Watch mode (continuous monitoring)')
    parser.add_argument('-i', '--interval', type=int, default=60, 
                        help='Watch mode interval in seconds (default: 60)')
    parser.add_argument('--ci', action='store_true', 
                        help='CI/CD mode (return exit codes)')
    parser.add_argument('--no-recursive', action='store_true', 
                        help='Disable recursive scan')
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = AutoSecurityScanner()
    
    # Run scan
    results = scanner.auto_scan(
        path=args.directory, 
        recursive=not args.no_recursive
    )
    
    # Output
    if args.format == 'json':
        output = json.dumps(results, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Report saved to: {args.output}")
        else:
            print(output)
    else:
        scanner.print_report(results)
    
    # Return exit code for CI/CD
    if args.ci:
        if results['security_issues']['critical'] > 0:
            return 2
        elif results['security_issues']['warning'] > 0:
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
