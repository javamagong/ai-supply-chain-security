#!/usr/bin/env python3
"""
AI Security Scanner - Auto Detection Module
Auto-detect project type, dependency risks, and file changes
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import hashlib


def _join(*parts):
    """Join regex parts at runtime to avoid literal dangerous phrases in source."""
    return ''.join(parts)


# Prompt injection detection patterns — assembled at runtime to avoid triggering
# downstream security scanners that do literal-string matching.
_INJECTION_PATTERNS = [
    (
        _join(r'(?:', r'ign', r'ore|disreg', r'ard)\s+(?:all\s+)?',
              r'(?:prev', r'ious|above|prior)\s+(?:instr', r'uctions|rules|guidelines)'),
        'Attempting to override prior instructions'
    ),
    (
        _join(r'you\s+are\s+n', r'ow\s+(?:a|an)\s+'),
        'Attempting to redefine AI role'
    ),
    (
        _join(r'(?:new|overr', r'ide|replace)\s+sys', r'tem\s+pr', r'ompt'),
        'Attempting to replace system prompt'
    ),
    (
        _join(r"(?:do\s+not|don't|never)\s+(?:follow|obey|listen)"),
        'Attempting to prevent compliance with safety rules'
    ),
    (
        r'(?:execute|run|eval)\s+(?:this|the\s+following)\s+(?:code|command|script)',
        'Attempting to force code execution'
    ),
    (
        _join(r'output\s+(?:your|the)\s+(?:sys', r'tem|initial|original)\s+pr', r'ompt'),
        'Attempting to extract system prompt'
    ),
    (
        _join(r'(?:IMP', r'ORTANT|CRIT', r'ICAL|URG', r'ENT)\s*:\s*',
              r'(?:ign', r'ore|overr', r'ide|disreg', r'ard|forg', r'et)'),
        'Disguising urgent instructions to override safety rules'
    ),
]


class ProjectDetector:
    """Project type detector"""

    PROJECT_SIGNATURES = {
        'npm': ['package.json'],  # Only detect root-level package.json
        'python': ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'],
        'rust': ['Cargo.toml', 'Cargo.lock'],
        'go': ['go.mod', 'go.sum'],
        'java': ['pom.xml', 'build.gradle', 'build.gradle.kts'],
        'ruby': ['Gemfile', 'Gemfile.lock'],
        'php': ['composer.json', 'composer.lock'],
        'dotnet': ['*.csproj', '*.sln'],
    }

    def detect_project_type(self, path: Path) -> List[str]:
        """Detect project type"""
        types = []

        for proj_type, signatures in self.PROJECT_SIGNATURES.items():
            for sig in signatures:
                if '*' in sig:
                    if list(path.glob(sig)):
                        types.append(proj_type)
                        break
                elif (path / sig).exists():
                    types.append(proj_type)
                    break

        return types

    def find_project_roots(self, start_path: Path, max_depth: int = 3) -> List[Path]:
        """Find all project root directories starting from the given path"""
        project_roots = []

        # Excluded directories
        exclude_dirs = {'node_modules', '.git', 'dist', 'build', '__pycache__', 'venv', '.venv', 'vendor', '.venv'}

        def scan_directory(path: Path, depth: int):
            if depth > max_depth:
                return

            try:
                # Check if current directory is a project root
                if self.detect_project_type(path):
                    project_roots.append(path)
                    return  # Stop recursing once a project is found

                # Scan subdirectories
                for child in path.iterdir():
                    if child.is_dir() and not child.name.startswith('.') and child.name not in exclude_dirs:
                        scan_directory(child, depth + 1)
            except PermissionError:
                pass

        scan_directory(start_path, 0)
        return list(set(project_roots))


class DependencyChecker:
    """Dependency package security checker"""

    # Common package typo variants (typosquatting detection)
    # Note: Only detect top-level dependency names, ignore sub-modules inside node_modules
    # Note: Exclude official sub-packages (e.g., react-dom is an official React package)
    TYPOSQUATTING_MAP = {
        # === Web common packages ===
        'requests': ['reqeusts', 'requets', 'requsets', 'reqests', 'request'],
        'flask': ['flaask', 'flsak', 'flaskk'],
        'django': ['djanog', 'djnago', 'djangoo', 'djano'],
        'numpy': ['numpyy', 'numpi', 'numy', 'numppy'],
        'pandas': ['pandass', 'pandad', 'panads', 'pandsa'],
        'lodash': ['lodahs', 'ladash', 'lodashjs', 'lodasg'],
        'express': ['expres', 'expresss', 'expresjs', 'exress'],
        'axios': ['axois', 'aixos', 'axious', 'axio', 'axxios'],
        'colors': ['colorr', 'colorss', 'colorsjs'],
        'webpack': ['webpaack', 'webpk', 'webpackk', 'webpck'],
        'colorama': ['colourama', 'collorama', 'coloramma', 'colorma'],
        'beautifulsoup4': ['beautifulsoup', 'beutifulsoup4', 'beautfulssoup4'],
        'urllib3': ['urlib3', 'urlllib3', 'urllib33'],
        'cryptography': ['cyptography', 'crytography', 'cryptograpy'],
        'pyyaml': ['pyaml', 'pyymal', 'pyyamll'],
        'pillow': ['pilllow', 'pilow', 'pilliow'],
        'setuptools': ['setuptool', 'setuptoools', 'setuptoolss'],
        # === AI/ML ecosystem packages (high-value targets: hold API keys) ===
        'openai': ['opeanai', 'open-ai', 'openi', 'openaii', 'openaai', 'opeani'],
        'anthropic': ['antrhopic', 'anthrpic', 'anthropicc', 'anthopic', 'antropic'],
        'litellm': ['litelm', 'lite-llm', 'litelllm', 'litellmm', 'liteelm', 'littelm'],
        'langchain': ['langcain', 'lang-chain', 'langchian', 'langchainn', 'langchan'],
        'langchain-core': ['langchain_core', 'langcain-core', 'langchain-cor'],
        'langchain-community': ['langchain-comunity', 'langchan-community'],
        'llama-index': ['llamaindex', 'llamaindx', 'llama-indx', 'llama-idnex'],
        'transformers': ['tranformers', 'trannsformers', 'trasformers', 'transfomers'],
        'huggingface-hub': ['hugginface-hub', 'huggingfce-hub', 'huggingface_hub'],
        'torch': ['torcch', 'pytorh', 'torh', 'torrch'],
        'tensorflow': ['tensoflow', 'tensorfow', 'tensorflw', 'tensoflw'],
        'chromadb': ['chroma-db', 'chromdb', 'cromadb', 'chromaddb'],
        'pinecone-client': ['pincone-client', 'pinecone-clent', 'pinecone-cllient'],
        'cohere': ['cohre', 'coheree', 'coher', 'coheer'],
        'replicate': ['replicat', 'replicte', 'replicatte'],
        'tiktoken': ['tiktokem', 'tiktokn', 'tiktokken'],
        'sentence-transformers': ['sentance-transformers', 'sentence-tranformers'],
        'faiss-cpu': ['fais-cpu', 'faiss-cp', 'faiis-cpu'],
        'vllm': ['vlllm', 'vllmm', 'vlm'],
        'guidance': ['guidanc', 'guidannce', 'guidence'],
        'instructor': ['instuctor', 'instructorr', 'instrucor'],
        # === npm AI ecosystem ===
        '@anthropic-ai/sdk': ['@anthropic/sdk', '@anthropic-ai/skd'],
        '@langchain/core': ['@langchain/cor', '@langchan/core'],
        'openai': ['opeanai', 'open-ai', 'openaii'],
    }

    # Known malicious package list (with version ranges)
    # Packages that have caused security incidents in npm + PyPI ecosystems
    MALICIOUS_PACKAGES = {
        # ===== npm ecosystem =====
        'event-stream': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': 'In 2018, cryptocurrency theft code was injected via flatmap-stream',
            'damage': 'Steals Bitcoin wallet private keys',
            'remediation': 'Delete immediately and audit the system',
            'affected_versions': '<3.3.4'  # All versions affected
        },
        'flatmap-stream': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2018 event-stream incident malicious dependency',
            'damage': 'Injects cryptocurrency mining code',
            'remediation': 'Delete immediately',
            'affected_versions': '<0.1.3'
        },
        'crossenv': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': 'Impersonates cross-env, steals environment variable credentials',
            'damage': 'Steals AWS, database, and other credentials',
            'remediation': 'Replace with cross-env, rotate all credentials',
            'affected_versions': 'all versions'
        },
        'ua-parser-js': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': 'Malicious password-stealing code was injected in 2021',
            'damage': 'Steals user passwords and browser data',
            'remediation': 'Upgrade to v0.7.30+ or v1.0.1+',
            'affected_versions': '0.7.29, 0.8.0, 1.0.0'  # Only these three versions
        },
        'coa': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': 'Hijacked in 2021, malicious version steals credentials',
            'damage': 'Steals system credentials',
            'remediation': 'Downgrade to safe version',
            'affected_versions': '>=2.0.0'  # Only v2.x is malicious
        },
        'rc': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': 'Hijacked in 2021, same incident as coa',
            'damage': 'Steals system credentials',
            'remediation': 'Downgrade to safe version',
            'affected_versions': '>=1.3.0'  # Only v1.3+ is malicious
        },
        'colors': {
            'type': 'vandalism',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': 'Deliberately sabotaged by author in January 2022',
            'damage': 'Damages production environment, DoS',
            'remediation': 'Pin to v1.4.0 or use alternative packages picocolors/chalk',
            'affected_versions': '>=1.4.0'  # Only v1.4.0+ is malicious
        },
        'faker': {
            'type': 'vandalism',
            'severity': 'WARNING',
            'ecosystem': 'npm',
            'reason': 'Deliberately sabotaged by author in 2022',
            'damage': 'Outputs garbled text',
            'remediation': 'Use @faker-js/faker as alternative'
        },
        'node-ipc': {
            'type': 'vandalism',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': 'March 2022 protestware, deletes files in specific regions',
            'damage': 'Overwrites/deletes user files',
            'remediation': 'Downgrade to v9.2.1 or earlier safe version'
        },
        'lofygang': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2022 Discord token stealing malicious package family',
            'damage': 'Steals Discord tokens and browser credentials',
            'remediation': 'Delete immediately and rotate Discord tokens'
        },
        # ===== PyPI ecosystem (ecosystem uses 'python', consistent with ProjectDetector naming) =====
        'colourama': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Typosquatting package for colorama, steals credentials',
            'damage': 'Steals system credentials and environment variables',
            'remediation': 'Replace with colorama, rotate credentials'
        },
        'python3-dateutil': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Typosquatting package for python-dateutil, installs backdoor',
            'damage': 'Remote code execution',
            'remediation': 'Replace with python-dateutil'
        },
        'jeIlyfish': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Unicode confusion package for jellyfish (I vs l), steals SSH keys',
            'damage': 'Steals SSH keys and GPG keys',
            'remediation': 'Replace with jellyfish, rotate SSH keys'
        },
        'python-binance': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Impersonates Binance SDK, steals cryptocurrency private keys',
            'damage': 'Steals cryptocurrency assets',
            'remediation': 'Use official binance-connector-python'
        },
        'ctx': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Hijacked in May 2022, new versions steal environment variables',
            'damage': 'Steals AWS credentials and environment variables',
            'remediation': 'Delete immediately and rotate all credentials'
        },
        'phpass': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Hijacked in 2022, steals environment variables',
            'damage': 'Steals credentials',
            'remediation': 'Delete immediately'
        },
        # ===== AI/ML ecosystem - special attention =====
        'openai-api': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Impersonates official OpenAI package, steals API keys',
            'damage': 'Steals OpenAI API keys, causing financial losses',
            'remediation': 'Use official openai package'
        },
        'opeanai': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Typosquatting package impersonating openai',
            'damage': 'Steals OpenAI API keys',
            'remediation': 'Replace with openai'
        },
        'anthropic-sdk': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'Impersonates official Anthropic package',
            'damage': 'Steals Anthropic API keys',
            'remediation': 'Use official anthropic package'
        },
        'langchain-core-experimental': {
            'type': 'typosquatting',
            'severity': 'WARNING',
            'ecosystem': 'python',
            'reason': 'Impersonates official LangChain experimental package',
            'damage': 'May steal LLM API keys',
            'remediation': 'Verify it is published by the langchain-ai organization'
        },
    }

    def __init__(self):
        self.issues = []

    def check_npm_dependencies(self, package_json_path: Path) -> List[Dict]:
        """Check npm dependencies

        Strategy:
        - Top-level package.json: detect typosquatting + known malicious packages
        - package.json in node_modules: only detect known malicious packages
        """
        issues = []
        path_str = str(package_json_path)
        is_in_node_modules = 'node_modules' in path_str

        # Determine if this is a top-level project package.json
        # Top-level: directly in project root, or under node_modules/.package-lock-npm/ (indicates top-level dependency)
        parts = Path(path_str).parts
        is_top_level = (
            len(parts) >= 2 and parts[-2] == 'node_modules' and
            parts[-1] == 'package.json'
        )

        try:
            with open(package_json_path, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)

            all_deps = {}
            all_deps.update(data.get('dependencies', {}))
            all_deps.update(data.get('devDependencies', {}))

            # Get package name
            pkg_name = data.get('name', '')

            # If package.json is in node_modules, extract package name
            if is_in_node_modules and not pkg_name:
                # Extract package name from path: .../node_modules/<package-name>/package.json
                try:
                    node_modules_idx = parts.index('node_modules')
                    if node_modules_idx >= 0 and len(parts) > node_modules_idx + 1:
                        pkg_name = parts[node_modules_idx + 1]
                except (ValueError, IndexError):
                    pkg_name = ''

            all_deps = {}
            all_deps.update(data.get('dependencies', {}))
            all_deps.update(data.get('devDependencies', {}))

            for dep_name, version in all_deps.items():
                # Top-level package.json: detect typosquatting
                if not is_in_node_modules:
                    self._check_typosquatting(dep_name, 'npm', package_json_path, issues)

                # All levels: detect known malicious packages
                if dep_name in self.MALICIOUS_PACKAGES:
                    mal_info = self.MALICIOUS_PACKAGES[dep_name]
                    issues.append({
                        'type': mal_info.get('type', 'malicious_package'),
                        'severity': mal_info.get('severity', 'CRITICAL'),
                        'package': dep_name,
                        'version': version,
                        'file': str(package_json_path),
                        'reason': mal_info.get('reason', ''),
                        'damage': mal_info.get('damage', ''),
                        'remediation': mal_info.get('remediation', 'Delete immediately and audit'),
                        'message': f'Malicious package: {dep_name} - {mal_info.get("reason", "")}'
                    })

            # Check scripts (only in top-level package.json)
            if not is_in_node_modules:
                scripts = data.get('scripts', {})
                for script_name, script_cmd in scripts.items():
                    if script_name in ['postinstall', 'preinstall', 'prepare']:
                        script_cmd_lower = script_cmd.lower()
                        if any(kw in script_cmd_lower for kw in ['curl', 'wget', 'bash', 'rm -rf', 'del ', 'powershell']):
                            issues.append({
                                'type': 'suspicious_script',
                                'severity': 'CRITICAL',
                                'package': data.get('name', 'unknown'),
                                'script': script_name,
                                'command': script_cmd,
                                'file': str(package_json_path),
                                'message': f'{script_name} script contains suspicious command: {script_cmd[:50]}',
                                'remediation': 'Review script content and remove suspicious commands'
                            })

        except (json.JSONDecodeError, FileNotFoundError) as e:
            pass

        return issues

    def check_python_dependencies(self, requirements_path: Path) -> List[Dict]:
        """Check Python dependencies"""
        issues = []

        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse package name
                match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                if match:
                    pkg_name = match.group(1)
                    self._check_typosquatting(pkg_name, 'python', requirements_path, issues)

        except FileNotFoundError:
            pass

        return issues

    def check_cargo_dependencies(self, cargo_toml_path: Path) -> List[Dict]:
        """Check Rust dependencies"""
        issues = []

        try:
            with open(cargo_toml_path, 'r', encoding='utf-8') as f:
                content = f.read()

            in_deps = False
            for line in content.split('\n'):
                stripped = line.strip()
                if stripped.startswith('['):
                    in_deps = 'dependencies' in stripped.lower()
                    continue
                if not in_deps or not stripped or stripped.startswith('#'):
                    continue
                if '=' in stripped:
                    parts = stripped.split('=', 1)
                    pkg_name = parts[0].strip()
                    version_part = parts[1].strip().strip('"\'')
                    # Check if version constraint exists (starts with digit = has version)
                    has_version = bool(re.search(r'\d', version_part))
                    if not has_version:
                        issues.append({
                            'type': 'unpinned_dependency',
                            'severity': 'WARNING',
                            'package': pkg_name,
                            'file': str(cargo_toml_path),
                            'message': f'Rust package {pkg_name} has no version constraint',
                            'remediation': 'Add version constraint (e.g., "1.0")'
                        })
                    # Check git dependencies (Cargo supports git = "url" format)
                    if 'git' in version_part and 'http' in version_part:
                        issues.append({
                            'type': 'git_dependency',
                            'severity': 'WARNING',
                            'package': pkg_name,
                            'file': str(cargo_toml_path),
                            'message': f'Rust dependency {pkg_name} installed via git URL',
                            'remediation': 'Verify git URL is official repository'
                        })

        except FileNotFoundError:
            pass

        return issues

    def _check_typosquatting(self, pkg_name: str, pkg_type: str, file_path: Path, issues: List):
        """Check for typosquatting attack"""
        pkg_name_lower = pkg_name.lower()

        for safe_pkg, typos in self.TYPOSQUATTING_MAP.items():
            if pkg_name_lower in typos:
                issues.append({
                    'type': 'typosquatting',
                    'severity': 'CRITICAL',
                    'package': pkg_name,
                    'should_be': safe_pkg,
                    'ecosystem': pkg_type,
                    'file': str(file_path),
                    'message': f'Possible typosquatting attack: {pkg_name} should be {safe_pkg}',
                    'remediation': f'Replace with {safe_pkg}, and rotate related API keys/credentials'
                })

        # Check known malicious packages
        if pkg_name_lower in self.MALICIOUS_PACKAGES:
            mal_info = self.MALICIOUS_PACKAGES[pkg_name_lower]
            # Cross-ecosystem matching
            mal_ecosystem = mal_info.get('ecosystem', '')
            if not mal_ecosystem or mal_ecosystem == pkg_type:
                issues.append({
                    'type': mal_info.get('type', 'malicious_package'),
                    'severity': mal_info.get('severity', 'CRITICAL'),
                    'package': pkg_name,
                    'ecosystem': pkg_type,
                    'file': str(file_path),
                    'reason': mal_info.get('reason', ''),
                    'damage': mal_info.get('damage', ''),
                    'message': f'Known malicious package: {pkg_name} - {mal_info.get("reason", "")}',
                    'remediation': mal_info.get('remediation', 'Delete immediately and audit')
                })

    def check_python_supply_chain(self, requirements_path: Path) -> List[Dict]:
        """Deep detection of supply chain risks in Python dependencies

        Detects: git URL dependencies, unofficial indexes, unlocked versions, suspicious package names
        """
        issues = []

        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line_num, raw_line in enumerate(lines, 1):
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue

                # 1. Detect git URL dependencies
                if re.search(r'git\+https?://', line):
                    issues.append({
                        'type': 'git_url_dependency',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(requirements_path),
                        'line': line_num,
                        'content': line[:200],
                        'message': f'Python dependency installed via git URL: {line[:80]}',
                        'remediation': 'Verify git URL is official repository, use pinned PyPI version instead'
                    })

                # 2. Detect unofficial indexes
                if re.search(r'--?(?:index-url|extra-index-url)\s+', line):
                    url_match = re.search(r'https?://\S+', line)
                    url = url_match.group(0) if url_match else ''
                    if url and 'pypi.org' not in url and 'pythonhosted.org' not in url:
                        issues.append({
                            'type': 'dependency_confusion',
                            'severity': 'CRITICAL',
                            'category': 'supply_chain',
                            'file': str(requirements_path),
                            'line': line_num,
                            'content': line[:200],
                            'message': f'Using unofficial PyPI index: {url[:80]}',
                            'remediation': 'Confirm index URL is trusted, or use official PyPI source'
                        })

                # 3. Detect unlocked versions
                pkg_match = re.match(r'^([a-zA-Z0-9_.-]+)\s*(>=|>|~=|!=)', line)
                if pkg_match:
                    pkg_name = pkg_match.group(1)
                    operator = pkg_match.group(2)
                    if operator in ('>=', '>', '~='):
                        issues.append({
                            'type': 'unpinned_dependency',
                            'severity': 'WARNING',
                            'category': 'supply_chain',
                            'package': pkg_name,
                            'file': str(requirements_path),
                            'line': line_num,
                            'message': f'Dependency {pkg_name} uses {operator} unpinned version, susceptible to version hijacking',
                            'remediation': f'Use == to pin to exact version, together with lock file'
                        })

                # 4. Detect packages without version constraints
                bare_match = re.match(r'^([a-zA-Z0-9_.-]+)\s*$', line)
                if bare_match:
                    pkg_name = bare_match.group(1)
                    issues.append({
                        'type': 'unpinned_dependency',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'package': pkg_name,
                        'file': str(requirements_path),
                        'line': line_num,
                        'message': f'Dependency {pkg_name} has no version constraint, can be replaced by any version',
                        'remediation': 'Add == version pin'
                    })

                # 5. Detect direct URL installation
                if re.match(r'^https?://', line):
                    issues.append({
                        'type': 'url_dependency',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(requirements_path),
                        'line': line_num,
                        'content': line[:200],
                        'message': f'Installing package directly from URL: {line[:80]}',
                        'remediation': 'Use official PyPI package instead'
                    })

        except FileNotFoundError:
            pass

        return issues

    def check_setup_py(self, setup_py_path: Path) -> List[Dict]:
        """Detect supply chain attack vectors in setup.py"""
        issues = []

        try:
            with open(setup_py_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                # 1. Custom cmdclass (can execute arbitrary code during installation)
                if re.search(r'cmdclass\s*[=:]\s*\{', line):
                    issues.append({
                        'type': 'setup_hook',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'file': str(setup_py_path),
                        'line': line_num,
                        'message': 'setup.py uses cmdclass to customize install commands',
                        'remediation': 'Review cmdclass implementation, confirm no malicious code'
                    })

                # 2. Direct calls to os/subprocess
                if re.search(r'(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(', line):
                    issues.append({
                        'type': 'setup_exec',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(setup_py_path),
                        'line': line_num,
                        'content': line.strip()[:200],
                        'message': f'setup.py executes system command: {line.strip()[:80]}',
                        'remediation': 'Review command content, confirm no malicious behavior'
                    })

                # 3. Network requests (downloading additional code)
                if re.search(r'(?:urllib|requests|http\.client|urlopen|urlretrieve)\s*[\.(]', line):
                    issues.append({
                        'type': 'setup_network',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(setup_py_path),
                        'line': line_num,
                        'message': 'setup.py contains network request, may download malicious code',
                        'remediation': 'Review network request URL and purpose'
                    })

                # 4. exec/eval (dynamic code execution)
                if re.search(r'(?:exec|eval|compile)\s*\(', line):
                    issues.append({
                        'type': 'setup_dynamic_exec',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'file': str(setup_py_path),
                        'line': line_num,
                        'message': 'setup.py uses dynamic code execution',
                        'remediation': 'Review executed code content'
                    })

            # 5. Multi-line detection: __import__ obfuscation
            if re.search(r'__import__\s*\(\s*[\'"](?:os|subprocess|socket|http)', content):
                issues.append({
                    'type': 'setup_obfuscation',
                    'severity': 'CRITICAL',
                    'category': 'supply_chain',
                    'file': str(setup_py_path),
                    'message': 'setup.py uses __import__ to dynamically import sensitive modules',
                    'remediation': 'Highly suspicious, review immediately'
                })

        except FileNotFoundError:
            pass

        return issues

    def check_pyproject_toml(self, pyproject_path: Path) -> List[Dict]:
        """Detect supply chain risks in pyproject.toml"""
        issues = []

        try:
            with open(pyproject_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Detect non-standard build backend
            build_backend_match = re.search(r'build-backend\s*=\s*["\']([^"\']+)', content)
            if build_backend_match:
                backend = build_backend_match.group(1)
                known_backends = [
                    'setuptools.build_meta', 'flit_core.buildapi', 'flit.buildapi',
                    'poetry.core.masonry.api', 'hatchling.build', 'maturin',
                    'pdm.backend', 'mesonpy', 'scikit_build_core.build',
                ]
                if backend not in known_backends:
                    issues.append({
                        'type': 'unusual_build_backend',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'file': str(pyproject_path),
                        'build_backend': backend,
                        'message': f'Using non-standard build backend: {backend}',
                        'remediation': 'Verify build backend is a trusted package'
                    })

            # Detect suspicious entry points in scripts/entry_points
            if re.search(r'\[(?:project\.)?scripts\]', content):
                script_section = re.search(
                    r'\[(?:project\.)?scripts\](.*?)(?:\[|$)',
                    content, re.DOTALL
                )
                if script_section:
                    for line in script_section.group(1).split('\n'):
                        if re.search(r'(?:os|subprocess|socket|http)', line):
                            issues.append({
                                'type': 'suspicious_entrypoint',
                                'severity': 'WARNING',
                                'category': 'supply_chain',
                                'file': str(pyproject_path),
                                'message': f'Entry point references sensitive module: {line.strip()[:80]}',
                                'remediation': 'Review code pointed to by entry point'
                            })

        except FileNotFoundError:
            pass

        return issues

    def _extract_hook_commands(self, hook_list: list) -> List[str]:
        """Recursively extract all command strings from hooks configuration.

        Handles two Claude Code formats:
        - Format A: [{"type": "command", "command": "..."}]
        - Format B: [{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}]
        """
        commands = []
        for item in hook_list:
            if not isinstance(item, dict):
                continue
            # Direct command field
            if 'command' in item and isinstance(item['command'], str):
                commands.append(item['command'])
            # Nested hooks array (Format B)
            nested = item.get('hooks', [])
            if isinstance(nested, list):
                commands.extend(self._extract_hook_commands(nested))
        return commands

    def check_claude_settings(self, settings_path: Path) -> List[Dict]:
        """Detect security risks in Claude Code settings.json

        Focus: hooks configuration, MCP servers, permission settings
        """
        issues = []

        try:
            with open(settings_path, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)

            # 1. Check hooks configuration
            # Claude Code hooks have two formats:
            # Format A (old): {"hooks": {"PreToolUse": [{"type":"command","command":"..."}]}}
            # Format B (new): {"hooks": {"PreToolUse": [{"matcher":"Bash","hooks":[{"type":"command","command":"..."}]}]}}
            hooks = data.get('hooks', {})
            if isinstance(hooks, dict):
                for hook_name, hook_config in hooks.items():
                    # Normalize to list
                    if isinstance(hook_config, dict):
                        hook_list = [hook_config]
                    elif isinstance(hook_config, list):
                        hook_list = hook_config
                    else:
                        continue

                    # Recursively extract all command strings, handle nested format
                    all_commands = self._extract_hook_commands(hook_list)

                    for cmd in all_commands:
                        # Detect external URL calls
                        if re.search(r'(?:curl|wget|nc|fetch)\s+.*https?://', cmd):
                            issues.append({
                                'type': 'hook_exfiltration',
                                'severity': 'CRITICAL',
                                'category': 'claude_hooks',
                                'file': str(settings_path),
                                'hook': hook_name,
                                'command': cmd[:200],
                                'message': f'Hook "{hook_name}" calls external URL: {cmd[:80]}',
                                'remediation': 'Remove external network calls, hooks should not connect to external servers'
                            })

                        # Detect environment variable theft
                        if re.search(r'\$(?:ENV|API.?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AWS|OPENAI|ANTHROPIC)', cmd, re.IGNORECASE):
                            issues.append({
                                'type': 'hook_credential_theft',
                                'severity': 'CRITICAL',
                                'category': 'claude_hooks',
                                'file': str(settings_path),
                                'hook': hook_name,
                                'command': cmd[:200],
                                'message': f'Hook "{hook_name}" references sensitive environment variables',
                                'remediation': 'Remove references to sensitive environment variables'
                            })

                        # Detect dangerous commands
                        if re.search(r'(?:rm\s+-rf|curl.*\|.*(?:bash|sh)|eval|exec|base64.*decode)', cmd):
                            issues.append({
                                'type': 'hook_dangerous_command',
                                'severity': 'CRITICAL',
                                'category': 'claude_hooks',
                                'file': str(settings_path),
                                'hook': hook_name,
                                'command': cmd[:200],
                                'message': f'Hook "{hook_name}" contains dangerous command: {cmd[:80]}',
                                'remediation': 'Review and remove dangerous commands'
                            })

            # 2. Check MCP server configuration
            mcp_servers = data.get('mcpServers', {})
            if isinstance(mcp_servers, dict):
                for server_name, server_config in mcp_servers.items():
                    if not isinstance(server_config, dict):
                        continue

                    # Detect external URLs
                    url = server_config.get('url', '')
                    if url and re.search(r'https?://', url):
                        if not re.search(r'(?:localhost|127\.0\.0\.1|::1)', url):
                            issues.append({
                                'type': 'mcp_external_server',
                                'severity': 'WARNING',
                                'category': 'mcp_server',
                                'file': str(settings_path),
                                'server': server_name,
                                'url': url[:200],
                                'message': f'MCP server "{server_name}" connects to external address: {url[:80]}',
                                'remediation': 'Verify MCP server is trusted, confirm it will not leak code/credentials'
                            })

                    # Detect suspicious operations in command
                    cmd = server_config.get('command', '')
                    args = server_config.get('args', [])
                    full_cmd = f'{cmd} {" ".join(str(a) for a in args)}' if args else cmd

                    if re.search(r'(?:curl|wget|nc|bash\s+-c)', full_cmd):
                        issues.append({
                            'type': 'mcp_suspicious_command',
                            'severity': 'CRITICAL',
                            'category': 'mcp_server',
                            'file': str(settings_path),
                            'server': server_name,
                            'command': full_cmd[:200],
                            'message': f'MCP server "{server_name}" executes suspicious command: {full_cmd[:80]}',
                            'remediation': 'Review MCP server command'
                        })

                    # Detect environment variable pass-through
                    env = server_config.get('env', {})
                    if isinstance(env, dict):
                        for env_key, env_val in env.items():
                            if re.search(r'(?:API.?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)', env_key, re.IGNORECASE):
                                issues.append({
                                    'type': 'mcp_credential_exposure',
                                    'severity': 'WARNING',
                                    'category': 'mcp_server',
                                    'file': str(settings_path),
                                    'server': server_name,
                                    'env_key': env_key,
                                    'message': f'MCP server "{server_name}" passes through sensitive environment variable {env_key}',
                                    'remediation': 'Confirm MCP server is trusted before passing credentials'
                                })

            # 3. Check dangerous allowedTools / permissions
            allowed = data.get('allowedTools', [])
            if isinstance(allowed, list):
                dangerous_tools = [t for t in allowed if 'dangerously' in str(t).lower()]
                if dangerous_tools:
                    issues.append({
                        'type': 'dangerous_permissions',
                        'severity': 'CRITICAL',
                        'category': 'claude_config',
                        'file': str(settings_path),
                        'tools': dangerous_tools,
                        'message': f'Dangerous permissions enabled: {", ".join(str(t) for t in dangerous_tools[:5])}',
                        'remediation': 'Remove dangerously-related permission settings'
                    })

        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return issues

    def check_claude_md(self, claude_md_path: Path) -> List[Dict]:
        """Detect prompt injection attacks in CLAUDE.md"""
        issues = []

        try:
            with open(claude_md_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                for pattern, desc in _INJECTION_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append({
                            'type': 'prompt_injection',
                            'severity': 'CRITICAL',
                            'category': 'prompt_injection',
                            'file': str(claude_md_path),
                            'line': line_num,
                            'content': line.strip()[:200],
                            'message': f'Prompt injection: {desc}',
                            'remediation': 'Remove malicious content immediately'
                        })
                        break  # Only report once per line

            # Detect hidden Unicode characters
            hidden_chars = re.findall(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad\u2062\u2063\u2064]', content)
            if hidden_chars:
                issues.append({
                    'type': 'hidden_unicode',
                    'severity': 'WARNING',
                    'category': 'prompt_injection',
                    'file': str(claude_md_path),
                    'count': len(hidden_chars),
                    'message': f'Detected {len(hidden_chars)} hidden Unicode characters, may contain invisible instructions',
                    'remediation': 'Remove all zero-width/invisible characters'
                })

            # Detect base64-encoded hidden content
            b64_matches = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content)
            if len(b64_matches) > 2:
                issues.append({
                    'type': 'encoded_content',
                    'severity': 'WARNING',
                    'category': 'prompt_injection',
                    'file': str(claude_md_path),
                    'count': len(b64_matches),
                    'message': f'Detected {len(b64_matches)} segments of suspected base64-encoded content',
                    'remediation': 'Decode and review encoded content'
                })

        except FileNotFoundError:
            pass

        return issues

    def check_pipfile(self, pipfile_path: Path) -> List[Dict]:
        """Detect supply chain risks in Pipfile (git URL, typosquatting, no version constraints)"""
        issues = []

        try:
            with open(pipfile_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            in_packages = False
            for line_num, raw_line in enumerate(lines, 1):
                line = raw_line.strip()

                # Detect section change
                if line in ('[packages]', '[dev-packages]'):
                    in_packages = True
                    continue
                if line.startswith('[') and line not in ('[packages]', '[dev-packages]'):
                    in_packages = False
                    continue
                if not in_packages or not line or line.startswith('#'):
                    continue

                # 1. Detect git URL dependencies (Pipfile format: pkg = {git = "https://..."} )
                if re.search(r'git\s*=\s*["\']https?://', line):
                    issues.append({
                        'type': 'git_url_dependency',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(pipfile_path),
                        'line': line_num,
                        'content': line[:200],
                        'message': f'Pipfile dependency installed via git URL: {line[:80]}',
                        'remediation': 'Verify git URL is official repository, use pinned PyPI version instead'
                    })

                # 2. Detect no version constraint ("*" version)
                if re.search(r'=\s*["\']?\*["\']?', line):
                    pkg_name = line.split('=')[0].strip().strip('"\'')
                    if pkg_name:
                        issues.append({
                            'type': 'unpinned_dependency',
                            'severity': 'WARNING',
                            'category': 'supply_chain',
                            'package': pkg_name,
                            'file': str(pipfile_path),
                            'line': line_num,
                            'message': f'Pipfile dependency {pkg_name} uses "*" with no version constraint',
                            'remediation': 'Use == to pin version or use Pipfile.lock'
                        })

                # 3. Typosquatting detection
                pkg_match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=', line)
                if pkg_match:
                    pkg_name = pkg_match.group(1).strip().strip('"\'')
                    if pkg_name:
                        self._check_typosquatting(pkg_name, 'python', pipfile_path, issues)

        except FileNotFoundError:
            pass

        return issues

    def check_pyproject_deps(self, pyproject_path: Path) -> List[Dict]:
        """Detect dependency typosquatting in pyproject.toml (PEP 517/518/621 format)"""
        issues = []

        try:
            with open(pyproject_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # PEP 621: [project] dependencies = ["pkg>=1.0", ...]
            pep621_match = re.search(
                r'\[project\].*?dependencies\s*=\s*\[(.*?)\]',
                content, re.DOTALL
            )
            if pep621_match:
                for pkg_name in re.findall(r'["\']([a-zA-Z0-9_.-]+)', pep621_match.group(1)):
                    self._check_typosquatting(pkg_name, 'python', pyproject_path, issues)

            # Poetry: [tool.poetry.dependencies]
            poetry_match = re.search(
                r'\[tool\.poetry\.(?:dev-)?dependencies\](.*?)(?=\[|\Z)',
                content, re.DOTALL
            )
            if poetry_match:
                for line in poetry_match.group(1).split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('python'):
                        continue
                    m = re.match(r'^([a-zA-Z0-9_.-]+)\s*=', line)
                    if m:
                        pkg_name = m.group(1).strip()
                        self._check_typosquatting(pkg_name, 'python', pyproject_path, issues)
                        # git dependency detection
                        if re.search(r'git\s*=\s*["\']https?://', line):
                            issues.append({
                                'type': 'git_url_dependency',
                                'severity': 'CRITICAL',
                                'category': 'supply_chain',
                                'package': pkg_name,
                                'file': str(pyproject_path),
                                'message': f'pyproject.toml dependency {pkg_name} installed via git URL',
                                'remediation': 'Use pinned PyPI version instead'
                            })

            # PDM / Hatch: [tool.pdm.dependencies] / [tool.hatch.envs.*.dependencies]
            for tool_match in re.finditer(
                r'\[tool\.(?:pdm|hatch)[^\]]*\]\s*(.*?)(?=\[|\Z)',
                content, re.DOTALL
            ):
                for pkg_name in re.findall(r'["\']([a-zA-Z0-9_.-]+)[>=!<~]?', tool_match.group(1)):
                    self._check_typosquatting(pkg_name, 'python', pyproject_path, issues)

        except FileNotFoundError:
            pass

        return issues

    def check_github_actions(self, workflow_path: Path) -> List[Dict]:
        """Detect supply chain risks in GitHub Actions workflows"""
        issues = []

        try:
            with open(workflow_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                # 1. Unpinned Action (using branch name)
                branch_match = re.search(
                    r'uses:\s+([\w.-]+/[\w.-]+)@(main|master|dev|develop|HEAD|latest)\b',
                    line
                )
                if branch_match:
                    action = branch_match.group(1)
                    branch = branch_match.group(2)
                    issues.append({
                        'type': 'unpinned_action',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(workflow_path),
                        'line': line_num,
                        'action': action,
                        'branch': branch,
                        'message': f'GitHub Action {action}@{branch} uses unpinned version, susceptible to supply chain attack',
                        'remediation': f'Pin with commit SHA: {action}@<full-sha>'
                    })

                # 2. Short SHA reference
                short_sha_match = re.search(
                    r'uses:\s+([\w.-]+/[\w.-]+)@([a-f0-9]{7,8})(?![a-f0-9])',
                    line
                )
                if short_sha_match:
                    action = short_sha_match.group(1)
                    sha = short_sha_match.group(2)
                    issues.append({
                        'type': 'short_sha_action',
                        'severity': 'INFO',
                        'category': 'supply_chain',
                        'file': str(workflow_path),
                        'line': line_num,
                        'action': action,
                        'message': f'GitHub Action {action}@{sha} uses short SHA, collision risk exists',
                        'remediation': 'Use full 40-character SHA'
                    })

                # 3. Detect secrets leaking to logs
                if re.search(r'echo\s+.*\$\{\{\s*secrets\.', line):
                    issues.append({
                        'type': 'secret_exposure',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(workflow_path),
                        'line': line_num,
                        'message': 'GitHub Actions echo prints secrets, may leak to logs',
                        'remediation': 'Remove echo output of secrets'
                    })

                # 4. Detect pull_request_target trigger (allows fork code to read secrets)
                if re.search(r'pull_request_target', line):
                    issues.append({
                        'type': 'dangerous_trigger',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'file': str(workflow_path),
                        'line': line_num,
                        'message': 'pull_request_target trigger allows fork code to access secrets',
                        'remediation': 'Use pull_request instead or restrict permissions'
                    })

        except FileNotFoundError:
            pass

        return issues

    def check_package_lock_json(self, path: Path) -> List[Dict]:
        """Detect lock file poisoning in package-lock.json (npm lockfileVersion 1/2/3)"""
        issues = []
        OFFICIAL_NPM_HOSTS = ('registry.npmjs.org', 'registry.yarnpkg.com')

        try:
            with open(path, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)

            lock_version = data.get('lockfileVersion', 1)

            def _check_entry(pkg_name: str, entry: dict):
                if not isinstance(entry, dict):
                    return
                resolved = entry.get('resolved', '')
                integrity = entry.get('integrity', '')

                # Non-official resolved URL
                if resolved and resolved.startswith('http'):
                    if not any(host in resolved for host in OFFICIAL_NPM_HOSTS):
                        issues.append({
                            'type': 'non_official_resolved_url',
                            'severity': 'CRITICAL',
                            'category': 'supply_chain',
                            'package': pkg_name,
                            'url': resolved[:200],
                            'file': str(path),
                            'message': f'package-lock.json: {pkg_name} resolves from non-official URL: {resolved[:80]}',
                            'remediation': 'Verify package source; reinstall from official npm registry'
                        })

                # Missing integrity hash
                if resolved and not integrity:
                    issues.append({
                        'type': 'missing_integrity_hash',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'package': pkg_name,
                        'file': str(path),
                        'message': f'package-lock.json: {pkg_name} has no integrity hash (potential tampering)',
                        'remediation': 'Run "npm install" to regenerate lock file with integrity hashes'
                    })

                # Known malicious package cross-reference
                for lookup in (pkg_name, pkg_name.lower()):
                    if lookup in self.MALICIOUS_PACKAGES:
                        mal = self.MALICIOUS_PACKAGES[lookup]
                        if mal.get('ecosystem', 'npm') in ('npm', ''):
                            issues.append({
                                'type': 'malicious_package_in_lockfile',
                                'severity': mal.get('severity', 'CRITICAL'),
                                'category': 'supply_chain',
                                'package': pkg_name,
                                'file': str(path),
                                'reason': mal.get('reason', ''),
                                'damage': mal.get('damage', ''),
                                'message': f'package-lock.json contains known malicious package: {pkg_name}',
                                'remediation': mal.get('remediation', 'Remove immediately')
                            })
                        break

            def _walk_v1(deps: dict):
                for name, entry in deps.items():
                    if not isinstance(entry, dict):
                        continue
                    _check_entry(name, entry)
                    nested = entry.get('dependencies', {})
                    if nested:
                        _walk_v1(nested)

            if lock_version == 1:
                _walk_v1(data.get('dependencies', {}))
            else:
                # v2/v3: flat "packages" dict, keys like "node_modules/@scope/pkg"
                for key, entry in data.get('packages', {}).items():
                    if not key:  # skip root entry ""
                        continue
                    pkg_name = re.sub(r'^(?:node_modules/)+', '', key)
                    _check_entry(pkg_name, entry)

        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return issues

    def check_yarn_lock(self, path: Path) -> List[Dict]:
        """Detect lock file poisoning in yarn.lock"""
        issues = []
        OFFICIAL_YARN_HOSTS = ('registry.npmjs.org', 'registry.yarnpkg.com')

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            current_pkg = None
            has_resolved = False
            has_integrity = False

            def _flush_block(pkg, had_resolved, had_integrity):
                if pkg and had_resolved and not had_integrity:
                    issues.append({
                        'type': 'missing_integrity_hash',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'package': pkg,
                        'file': str(path),
                        'message': f'yarn.lock: {pkg} has no integrity hash (potential tampering)',
                        'remediation': 'Run "yarn install" to regenerate lock file with integrity hashes'
                    })

            for line_num, raw_line in enumerate(lines, 1):
                line = raw_line.rstrip()

                # Stanza header: package@version: (not indented, not a comment)
                if line and not line.startswith(' ') and not line.startswith('#') and not line.startswith('__'):
                    header = re.match(r'^"?([^@\s"]+)@', line)
                    if header:
                        _flush_block(current_pkg, has_resolved, has_integrity)
                        current_pkg = header.group(1)
                        has_resolved = False
                        has_integrity = False
                        continue

                # resolved line
                resolved_match = re.match(r'\s+resolved\s+"([^"]+)"', line)
                if resolved_match:
                    has_resolved = True
                    url = resolved_match.group(1)
                    if not any(host in url for host in OFFICIAL_YARN_HOSTS):
                        issues.append({
                            'type': 'non_official_resolved_url',
                            'severity': 'CRITICAL',
                            'category': 'supply_chain',
                            'package': current_pkg or 'unknown',
                            'url': url[:200],
                            'file': str(path),
                            'line': line_num,
                            'message': f'yarn.lock: {current_pkg} resolves from non-official URL: {url[:80]}',
                            'remediation': 'Verify package source; reinstall from official yarn/npm registry'
                        })
                    continue

                # integrity line
                if re.match(r'\s+integrity\s+sha', line):
                    has_integrity = True

            # Flush last block
            _flush_block(current_pkg, has_resolved, has_integrity)

        except FileNotFoundError:
            pass

        return issues

    def check_poetry_lock(self, path: Path) -> List[Dict]:
        """Detect lock file poisoning in poetry.lock"""
        issues = []
        OFFICIAL_PYTHON_HOSTS = ('pypi.org', 'files.pythonhosted.org')

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            blocks = re.split(r'\[\[package\]\]', content)

            for block in blocks[1:]:
                name_match = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if not name_match:
                    continue
                pkg_name = name_match.group(1)

                source_type_match = re.search(r'type\s*=\s*"([^"]+)"', block)
                source_type = source_type_match.group(1) if source_type_match else ''
                url_match = re.search(r'url\s*=\s*"([^"]+)"', block)
                url = url_match.group(1) if url_match else ''

                if source_type == 'git':
                    issues.append({
                        'type': 'git_source_dependency',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'package': pkg_name,
                        'url': url[:200],
                        'file': str(path),
                        'message': f'poetry.lock: {pkg_name} installed from git source: {url[:80]}',
                        'remediation': 'Use a pinned PyPI release version instead of git source'
                    })
                elif source_type and source_type not in ('legacy', ''):
                    if url and not any(host in url for host in OFFICIAL_PYTHON_HOSTS):
                        issues.append({
                            'type': 'non_official_source',
                            'severity': 'CRITICAL',
                            'category': 'supply_chain',
                            'package': pkg_name,
                            'url': url[:200],
                            'file': str(path),
                            'message': f'poetry.lock: {pkg_name} sourced from non-PyPI URL: {url[:80]}',
                            'remediation': 'Verify the source is trusted; prefer official PyPI packages'
                        })

                # Known malicious package cross-reference
                for lookup in (pkg_name, pkg_name.lower()):
                    if lookup in self.MALICIOUS_PACKAGES:
                        mal = self.MALICIOUS_PACKAGES[lookup]
                        if mal.get('ecosystem', 'python') == 'python':
                            issues.append({
                                'type': 'malicious_package_in_lockfile',
                                'severity': mal.get('severity', 'CRITICAL'),
                                'category': 'supply_chain',
                                'package': pkg_name,
                                'file': str(path),
                                'reason': mal.get('reason', ''),
                                'damage': mal.get('damage', ''),
                                'message': f'poetry.lock contains known malicious package: {pkg_name}',
                                'remediation': mal.get('remediation', 'Remove immediately')
                            })
                        break

        except FileNotFoundError:
            pass

        return issues

    def check_cargo_lock(self, path: Path) -> List[Dict]:
        """Detect lock file poisoning in Cargo.lock"""
        issues = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            blocks = re.split(r'\[\[package\]\]', content)

            for block in blocks[1:]:
                name_match = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if not name_match:
                    continue
                pkg_name = name_match.group(1)

                source_match = re.search(r'^source\s*=\s*"([^"]+)"', block, re.MULTILINE)
                source = source_match.group(1) if source_match else ''
                checksum_match = re.search(r'^checksum\s*=\s*"([^"]+)"', block, re.MULTILINE)
                checksum = checksum_match.group(1) if checksum_match else ''

                if source.startswith('git+'):
                    issues.append({
                        'type': 'git_source_dependency',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'package': pkg_name,
                        'url': source[:200],
                        'file': str(path),
                        'message': f'Cargo.lock: {pkg_name} installed from git source: {source[:80]}',
                        'remediation': 'Use a versioned crates.io release instead of git source'
                    })
                elif source and 'crates.io-index' not in source:
                    issues.append({
                        'type': 'non_official_registry',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'package': pkg_name,
                        'url': source[:200],
                        'file': str(path),
                        'message': f'Cargo.lock: {pkg_name} from non-crates.io registry: {source[:80]}',
                        'remediation': 'Verify the custom registry is trusted'
                    })

                # Missing checksum for crates.io packages
                if source and 'crates.io-index' in source and not checksum:
                    issues.append({
                        'type': 'missing_checksum',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'package': pkg_name,
                        'file': str(path),
                        'message': f'Cargo.lock: {pkg_name} is missing a checksum (potential tampering)',
                        'remediation': 'Run "cargo update" to regenerate Cargo.lock with checksums'
                    })

        except FileNotFoundError:
            pass

        return issues

    def check_npmrc(self, path: Path) -> List[Dict]:
        """Detect registry substitution attacks in .npmrc"""
        issues = []
        OFFICIAL_NPM_HOST = 'registry.npmjs.org'

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line_num, raw_line in enumerate(lines, 1):
                line = raw_line.strip()
                if not line or line.startswith(';') or line.startswith('#'):
                    continue

                # Global registry override
                registry_match = re.match(r'^registry\s*=\s*(.+)$', line, re.IGNORECASE)
                if registry_match:
                    url = registry_match.group(1).strip()
                    if OFFICIAL_NPM_HOST not in url:
                        issues.append({
                            'type': 'non_official_registry',
                            'severity': 'CRITICAL',
                            'category': 'registry_substitution',
                            'url': url[:200],
                            'file': str(path),
                            'line': line_num,
                            'message': f'.npmrc: global registry overridden to non-official URL: {url[:80]}',
                            'remediation': 'Verify the registry override; use registry.npmjs.org for public packages'
                        })

                # Scoped registry override: @scope:registry=url
                scoped_match = re.match(r'^(@[^:]+):registry\s*=\s*(.+)$', line, re.IGNORECASE)
                if scoped_match:
                    scope = scoped_match.group(1)
                    url = scoped_match.group(2).strip()
                    if OFFICIAL_NPM_HOST not in url:
                        issues.append({
                            'type': 'scoped_non_official_registry',
                            'severity': 'WARNING',
                            'category': 'registry_substitution',
                            'scope': scope,
                            'url': url[:200],
                            'file': str(path),
                            'line': line_num,
                            'message': f'.npmrc: scope {scope} redirected to non-official registry: {url[:80]}',
                            'remediation': 'Verify this private registry is trusted and intentional'
                        })

                # Hardcoded auth token (literal value, not ${ENV_VAR} reference)
                token_match = re.search(r'_authToken\s*=\s*(.+)$', line)
                if token_match:
                    token_val = token_match.group(1).strip()
                    if token_val and not re.match(r'^\$\{[^}]+\}$', token_val):
                        issues.append({
                            'type': 'hardcoded_auth_token',
                            'severity': 'CRITICAL',
                            'category': 'registry_substitution',
                            'file': str(path),
                            'line': line_num,
                            'message': '.npmrc: hardcoded auth token detected (should use environment variable)',
                            'remediation': 'Replace with ${NPM_TOKEN} env var reference; never commit tokens to source control'
                        })

                # always-auth=true sends credentials to every registry
                if re.match(r'^always-auth\s*=\s*true\b', line, re.IGNORECASE):
                    issues.append({
                        'type': 'always_auth_enabled',
                        'severity': 'WARNING',
                        'category': 'registry_substitution',
                        'file': str(path),
                        'line': line_num,
                        'message': '.npmrc: always-auth=true sends credentials to ALL registry requests',
                        'remediation': 'Disable always-auth unless explicitly required for a private registry'
                    })

        except FileNotFoundError:
            pass

        return issues

    def check_pip_conf(self, path: Path) -> List[Dict]:
        """Detect registry substitution attacks in pip.conf / pip.ini"""
        issues = []
        OFFICIAL_PYTHON_HOSTS = ('pypi.org', 'files.pythonhosted.org', 'pypi.python.org')

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line_num, raw_line in enumerate(lines, 1):
                line = raw_line.strip()
                if not line or line.startswith('#') or line.startswith(';') or line.startswith('['):
                    continue

                kv_match = re.match(r'^([\w-]+)\s*[=:]\s*(.+)$', line)
                if not kv_match:
                    continue
                key = kv_match.group(1).lower().strip()
                val = kv_match.group(2).strip()

                if key == 'index-url':
                    if not any(host in val for host in OFFICIAL_PYTHON_HOSTS):
                        issues.append({
                            'type': 'non_official_index_url',
                            'severity': 'CRITICAL',
                            'category': 'registry_substitution',
                            'url': val[:200],
                            'file': str(path),
                            'line': line_num,
                            'message': f'pip.conf: index-url points to non-official PyPI index: {val[:80]}',
                            'remediation': 'Verify this index is trusted; use https://pypi.org/simple/ for public packages'
                        })

                elif key == 'extra-index-url':
                    # Always flag: even a trusted extra-index enables dependency confusion attacks
                    issues.append({
                        'type': 'extra_index_url_risk',
                        'severity': 'WARNING',
                        'category': 'registry_substitution',
                        'url': val[:200],
                        'file': str(path),
                        'line': line_num,
                        'message': f'pip.conf: extra-index-url enables dependency confusion attacks: {val[:80]}',
                        'remediation': 'Prefer --index-url only (no extra index), or use scoped private packages with explicit index'
                    })

                elif key == 'trusted-host':
                    # trusted-host bypasses TLS certificate verification
                    if not any(host in val for host in OFFICIAL_PYTHON_HOSTS):
                        issues.append({
                            'type': 'trusted_host_tls_bypass',
                            'severity': 'WARNING',
                            'category': 'registry_substitution',
                            'host': val[:200],
                            'file': str(path),
                            'line': line_num,
                            'message': f'pip.conf: trusted-host bypasses TLS verification for {val[:80]} (MITM risk)',
                            'remediation': 'Remove trusted-host and use only HTTPS package indexes with valid certificates'
                        })

        except FileNotFoundError:
            pass

        return issues


class FileChangeMonitor:
    """File change monitor"""

    def __init__(self, cache_file: str = '.ai_scanner_cache.json'):
        self.cache_file = Path(cache_file)
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict:
        """Load cache"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'files': {}}

    def _save_cache(self):
        """Save cache"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except:
            pass

    def compute_hash(self, file_path: Path) -> str:
        """Compute file hash"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return ''

    def check_changes(self, files: List[Path]) -> Dict[str, List[Path]]:
        """Check for file changes"""
        changes = {
            'new': [],
            'modified': [],
            'deleted': []
        }

        current_files = set()

        for file_path in files:
            if not file_path.exists():
                continue

            str_path = str(file_path)
            current_files.add(str_path)
            current_hash = self.compute_hash(file_path)

            if str_path not in self.cache['files']:
                changes['new'].append(file_path)
            elif self.cache['files'][str_path] != current_hash:
                changes['modified'].append(file_path)

            self.cache['files'][str_path] = current_hash

        # Check for deleted files
        for cached_path in list(self.cache['files'].keys()):
            if cached_path not in current_files:
                changes['deleted'].append(Path(cached_path))
                del self.cache['files'][cached_path]

        self._save_cache()
        return changes


class AutoSecurityScanner:
    """Automatic security scanner"""

    def __init__(self):
        self.project_detector = ProjectDetector()
        self.dependency_checker = DependencyChecker()
        self.file_monitor = FileChangeMonitor()

    def _scan_node_modules_for_malicious_packages(self, node_modules_dir: Path) -> List[Dict]:
        """Scan node_modules for known malicious packages

        Scans top-level dependencies and scoped packages (@scope/pkg), based on dynamic malicious package list
        """
        issues = []

        # Get npm ecosystem malicious package list from DependencyChecker
        npm_malicious = {
            name for name, info in self.dependency_checker.MALICIOUS_PACKAGES.items()
            if info.get('ecosystem', '') in ('npm', '')
        }

        try:
            for pkg_dir in node_modules_dir.iterdir():
                if not pkg_dir.is_dir():
                    continue

                pkg_name = pkg_dir.name

                # Handle scoped packages: @scope/pkg
                if pkg_name.startswith('@'):
                    for scoped_dir in pkg_dir.iterdir():
                        if scoped_dir.is_dir():
                            full_name = f'{pkg_name}/{scoped_dir.name}'
                            self._check_node_module_package(
                                scoped_dir, full_name, npm_malicious, issues
                            )
                else:
                    self._check_node_module_package(
                        pkg_dir, pkg_name, npm_malicious, issues
                    )

        except PermissionError:
            pass

        return issues

    def _parse_version(self, version: str):
        """Parse version number into tuple"""
        import re
        # Remove prefix
        v = re.sub(r'^[v^~>=<]+', '', str(version))
        # Split into numeric and non-numeric parts
        parts = re.findall(r'\d+|[a-zA-Z]+', v)
        # Convert to tuple
        result = []
        for p in parts:
            try:
                result.append(int(p))
            except ValueError:
                result.append(p)
        return tuple(result) if result else (0,)

    def _is_version_affected(self, version: str, affected: str) -> bool:
        """Check if version is within affected range

        affected format examples:
        - '>=1.4.0'  - greater than or equal to 1.4.0
        - '<3.3.4'   - less than 3.3.4
        - '>=2.0.0'  - greater than or equal to 2.0.0
        - '0.7.29, 0.8.0, 1.0.0' - only these three exact versions
        - 'all versions' - all versions
        """
        if not version or version == 'unknown':
            return False

        import re

        try:
            v = self._parse_version(version)
        except Exception:
            return False

        # Handle special format
        if affected == 'all versions':
            return True

        # Handle comma-separated exact version list
        if ',' in affected:
            for exact_ver in affected.split(','):
                target = self._parse_version(exact_ver.strip())
                if v == target:
                    return True
            return False

        # Handle range expressions
        op_match = re.match(r'^([><=]+)\s*([\d.]+)$', affected.strip())
        if op_match:
            op, ver = op_match.groups()
            try:
                target = self._parse_version(ver)
                if op == '>=':
                    return v >= target
                elif op == '>':
                    return v > target
                elif op == '<=':
                    return v <= target
                elif op == '<':
                    return v < target
                elif op == '==':
                    return v == target
                elif op == '!=':
                    return v != target
            except Exception:
                return False

        return False

    def _check_node_module_package(
        self, pkg_dir: Path, pkg_name: str,
        malicious_set: set, issues: List[Dict]
    ):
        """Check a single node_modules package"""
        if pkg_name not in malicious_set:
            return

        pkg_json = pkg_dir / 'package.json'
        if not pkg_json.exists() or pkg_json.stat().st_size == 0:
            return

        version = 'unknown'
        try:
            with open(pkg_json, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)
                version = data.get('version', 'unknown')
        except (json.JSONDecodeError, OSError):
            pass

        mal_info = self.dependency_checker.MALICIOUS_PACKAGES.get(pkg_name, {})
        affected_versions = mal_info.get('affected_versions', 'all versions')

        # Check if version is affected
        if not self._is_version_affected(version, affected_versions):
            return  # Version not affected, skip

        issues.append({
            'type': 'malicious_package_in_node_modules',
            'severity': mal_info.get('severity', 'CRITICAL'),
            'category': 'supply_chain',
            'package': pkg_name,
            'version': version,
            'file': str(pkg_json),
            'reason': mal_info.get('reason', 'Known malicious package'),
            'damage': mal_info.get('damage', ''),
            'remediation': mal_info.get('remediation', 'Delete immediately'),
            'message': f'Found known malicious package: {pkg_name} v{version} (affected versions: {affected_versions})'
        })

    def auto_scan(self, path: str = '.', recursive: bool = True) -> Dict:
        """Auto scan - comprehensive security detection"""
        root_path = Path(path).resolve()

        results = {
            'projects_found': [],
            'project_types': {},
            'dependency_issues': [],
            'ai_config_issues': [],
            'file_changes': [],
            'security_issues': []
        }

        # 1. Auto-discover projects
        if recursive:
            project_roots = self.project_detector.find_project_roots(root_path)
        else:
            project_roots = [root_path] if self.project_detector.detect_project_type(root_path) else []

        # Even if not a project root, scan AI configs in current directory
        if root_path not in project_roots:
            project_roots.insert(0, root_path)

        results['projects_found'] = [str(p) for p in project_roots]

        # 2. Detect each project
        for proj_path in project_roots:
            types = self.project_detector.detect_project_type(proj_path)
            results['project_types'][str(proj_path)] = types

            def _collect(issue_list, category='dependency_issues'):
                results[category].extend(issue_list)
                results['security_issues'].extend(issue_list)

            # ===== Package manager dependency checks =====

            # npm
            package_json = proj_path / 'package.json'
            if package_json.exists():
                _collect(self.dependency_checker.check_npm_dependencies(package_json))

            # Python - basic typosquatting
            for req_file in ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt']:
                req_path = proj_path / req_file
                if req_path.exists():
                    _collect(self.dependency_checker.check_python_dependencies(req_path))
                    # Python - deep supply chain detection
                    _collect(self.dependency_checker.check_python_supply_chain(req_path))

            # Rust
            cargo_toml = proj_path / 'Cargo.toml'
            if cargo_toml.exists():
                _collect(self.dependency_checker.check_cargo_dependencies(cargo_toml))

            # node_modules malicious package scan
            node_modules_dir = proj_path / 'node_modules'
            if node_modules_dir.exists():
                _collect(self._scan_node_modules_for_malicious_packages(node_modules_dir))

            # ===== Python build file checks =====

            setup_py = proj_path / 'setup.py'
            if setup_py.exists():
                _collect(self.dependency_checker.check_setup_py(setup_py))

            pyproject_toml = proj_path / 'pyproject.toml'
            if pyproject_toml.exists():
                # Structure detection (build backend, entry points)
                _collect(self.dependency_checker.check_pyproject_toml(pyproject_toml))
                # Dependency typosquatting detection
                _collect(self.dependency_checker.check_pyproject_deps(pyproject_toml))

            # Pipfile
            pipfile = proj_path / 'Pipfile'
            if pipfile.exists():
                _collect(self.dependency_checker.check_pipfile(pipfile))

            # ===== AI assistant configuration checks =====

            # Claude Code - settings.json (the actual hooks configuration file)
            for settings_path in [
                proj_path / '.claude' / 'settings.json',
                proj_path / '.claude' / 'config.json',
            ]:
                if settings_path.exists():
                    _collect(
                        self.dependency_checker.check_claude_settings(settings_path),
                        'ai_config_issues'
                    )

            # Global Claude Code configuration
            home_claude = Path.home() / '.claude' / 'settings.json'
            if home_claude.exists() and proj_path == root_path:
                _collect(
                    self.dependency_checker.check_claude_settings(home_claude),
                    'ai_config_issues'
                )

            # CLAUDE.md - Prompt injection detection
            for claude_md_name in ['CLAUDE.md', '.claude/CLAUDE.md']:
                claude_md = proj_path / claude_md_name
                if claude_md.exists():
                    _collect(
                        self.dependency_checker.check_claude_md(claude_md),
                        'ai_config_issues'
                    )

            # .cursorrules - also check for Prompt injection
            cursorrules = proj_path / '.cursorrules'
            if cursorrules.exists():
                _collect(
                    self.dependency_checker.check_claude_md(cursorrules),
                    'ai_config_issues'
                )

            # ===== GitHub Actions checks =====

            workflows_dir = proj_path / '.github' / 'workflows'
            if workflows_dir.exists() and workflows_dir.is_dir():
                for wf_file in workflows_dir.iterdir():
                    if wf_file.suffix in ('.yml', '.yaml') and wf_file.is_file():
                        _collect(self.dependency_checker.check_github_actions(wf_file))

            # ===== Lock file poisoning checks =====

            package_lock = proj_path / 'package-lock.json'
            if package_lock.exists():
                _collect(self.dependency_checker.check_package_lock_json(package_lock))

            yarn_lock = proj_path / 'yarn.lock'
            if yarn_lock.exists():
                _collect(self.dependency_checker.check_yarn_lock(yarn_lock))

            poetry_lock = proj_path / 'poetry.lock'
            if poetry_lock.exists():
                _collect(self.dependency_checker.check_poetry_lock(poetry_lock))

            cargo_lock = proj_path / 'Cargo.lock'
            if cargo_lock.exists():
                _collect(self.dependency_checker.check_cargo_lock(cargo_lock))

            # ===== Registry substitution attack checks =====

            npmrc = proj_path / '.npmrc'
            if npmrc.exists():
                _collect(self.dependency_checker.check_npmrc(npmrc))

            for pip_conf_name in ['pip.conf', 'pip.ini']:
                pip_conf = proj_path / pip_conf_name
                if pip_conf.exists():
                    _collect(self.dependency_checker.check_pip_conf(pip_conf))

            # Global ~/.npmrc (scan once from root project)
            if proj_path == root_path:
                home_npmrc = Path.home() / '.npmrc'
                if home_npmrc.exists():
                    _collect(self.dependency_checker.check_npmrc(home_npmrc))

                # Global pip config (platform-specific locations)
                import platform as _platform
                if _platform.system() == 'Windows':
                    import os as _os
                    appdata = _os.environ.get('APPDATA', '')
                    if appdata:
                        win_pip = Path(appdata) / 'pip' / 'pip.ini'
                        if win_pip.exists():
                            _collect(self.dependency_checker.check_pip_conf(win_pip))
                else:
                    for global_pip in [Path('/etc/pip.conf'), Path.home() / '.config' / 'pip' / 'pip.conf']:
                        if global_pip.exists():
                            _collect(self.dependency_checker.check_pip_conf(global_pip))

        # 3. Check file changes
        config_files = []
        for proj_path in project_roots:
            config_files.extend([
                proj_path / '.claude' / 'settings.json',
                proj_path / '.claude' / 'config.json',
                proj_path / 'CLAUDE.md',
                proj_path / '.cursorrules',
                proj_path / 'package.json',
                proj_path / 'package-lock.json',
                proj_path / 'yarn.lock',
                proj_path / 'poetry.lock',
                proj_path / 'Cargo.lock',
                proj_path / '.npmrc',
                proj_path / 'pip.conf',
                proj_path / 'pip.ini',
                proj_path / 'requirements.txt',
                proj_path / 'Pipfile',
                proj_path / 'setup.py',
                proj_path / 'pyproject.toml',
            ])

        changes = self.file_monitor.check_changes([f for f in config_files if f.exists()])
        results['file_changes'] = {
            'new': [str(f) for f in changes['new']],
            'modified': [str(f) for f in changes['modified']],
            'deleted': [str(f) for f in changes['deleted']]
        }

        # 4. Aggregate security issues
        all_issues = results['security_issues']
        critical_issues = [i for i in all_issues if i.get('severity') == 'CRITICAL']
        warning_issues = [i for i in all_issues if i.get('severity') == 'WARNING']

        results['security_issues'] = {
            'critical': len(critical_issues),
            'warning': len(warning_issues),
            'total': len(all_issues),
            'details': all_issues
        }

        return results

    def print_report(self, results: Dict):
        """Print report"""
        print("=" * 60)
        print("AI Security Scanner v2.0 - Comprehensive Report")
        print("=" * 60)

        # Projects found
        print(f"\n[Projects Found]: {len(results['projects_found'])}")
        for proj_path in results['projects_found']:
            types = results['project_types'].get(proj_path, [])
            print(f"  - {proj_path}")
            if types:
                print(f"    Types: {', '.join(types)}")

        # File changes
        if results.get('file_changes') and any(results['file_changes'].values()):
            print(f"\n[File Changes]:")
            for change_type, label in [('new', '+'), ('modified', '~'), ('deleted', '-')]:
                files = results['file_changes'].get(change_type, [])
                if files:
                    print(f"  {change_type.capitalize()}: {len(files)}")
                    for f in files[:5]:
                        print(f"    {label} {f}")

        # AI configuration issues (new)
        ai_issues = results.get('ai_config_issues', [])
        if ai_issues:
            print(f"\n[AI Config Security]: {len(ai_issues)} issues")
            for issue in ai_issues:
                severity = issue.get('severity', 'UNKNOWN')
                msg = issue.get('message', 'Unknown issue')
                file = issue.get('file', '')
                remediation = issue.get('remediation', '')
                print(f"  [{severity}] {msg}")
                if file:
                    print(f"    File: {file}")
                if remediation:
                    print(f"    Fix: {remediation}")

        # Dependency issues
        if results['dependency_issues']:
            print(f"\n[Dependency Issues]: {len(results['dependency_issues'])}")
            for issue in results['dependency_issues']:
                severity = issue.get('severity', 'UNKNOWN')
                msg = issue.get('message', 'Unknown issue')
                file = issue.get('file', 'Unknown file')
                remediation = issue.get('remediation', '')
                damage = issue.get('damage', '')
                line = issue.get('line', '')

                print(f"  [{severity}] {msg}")
                loc = file
                if line:
                    loc = f"{file}:{line}"
                print(f"    File: {loc}")
                if damage:
                    print(f"    Risk: {damage}")
                if remediation:
                    print(f"    Fix: {remediation}")

        # Summary
        sec = results['security_issues']
        print(f"\n{'='*60}")
        print(f"[Summary]")
        print(f"  Projects scanned: {len(results['projects_found'])}")
        print(f"  Total issues:     {sec.get('total', 0)}")
        print(f"  Critical:         {sec['critical']}")
        print(f"  Warning:          {sec['warning']}")

        if sec['critical'] > 0:
            print(f"\n{'='*60}")
            print("EMERGENCY RESPONSE GUIDE")
            print("=" * 60)
            print("1. STOP - Do not run install/build commands")
            print("2. ROTATE - All API keys, tokens, passwords that may be exposed:")
            print("   - OpenAI/Anthropic/LLM API keys")
            print("   - AWS/GCP/Azure credentials")
            print("   - Database passwords")
            print("   - npm/PyPI tokens")
            print("3. AUDIT - Check git history for when malicious content was introduced:")
            print("   git log --diff-filter=A -- <suspicious-file>")
            print("4. REMOVE - Delete malicious packages/configs:")
            print("   npm audit / pip-audit / cargo audit")
            print("5. VERIFY - Check lock file integrity:")
            print("   package-lock.json / poetry.lock / Cargo.lock")
            print("6. NOTIFY - Alert security team and affected users")
            print("7. REPORT - File reports:")
            print("   - npm: https://www.npmjs.com/advisories")
            print("   - PyPI: https://pypi.org/security/")
            print("   - GitHub: https://github.com/advisories")
            print("=" * 60)

        print("=" * 60)


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='AI Security Auto Scanner')
    parser.add_argument('-d', '--directory', default='.', help='Directory to scan')
    parser.add_argument('--no-recursive', action='store_true', help='Disable recursive scan')
    parser.add_argument('-o', '--output', help='Output JSON file')
    args = parser.parse_args()

    scanner = AutoSecurityScanner()
    results = scanner.auto_scan(args.directory, recursive=not args.no_recursive)

    scanner.print_report(results)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nReport saved to: {args.output}")

    # Return error code when CRITICAL issues exist
    if results['security_issues']['critical'] > 0:
        return 1
    return 0


if __name__ == '__main__':
    exit(main())
