#!/usr/bin/env python3
"""
AI Security Scanner - Auto Detection Module
自动检测项目类型、依赖风险、文件变更
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import hashlib


class ProjectDetector:
    """项目类型检测器"""
    
    PROJECT_SIGNATURES = {
        'npm': ['package.json'],  # 只检测根目录的 package.json
        'python': ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'],
        'rust': ['Cargo.toml', 'Cargo.lock'],
        'go': ['go.mod', 'go.sum'],
        'java': ['pom.xml', 'build.gradle', 'build.gradle.kts'],
        'ruby': ['Gemfile', 'Gemfile.lock'],
        'php': ['composer.json', 'composer.lock'],
        'dotnet': ['*.csproj', '*.sln'],
    }
    
    def detect_project_type(self, path: Path) -> List[str]:
        """检测项目类型"""
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
        """从指定路径开始查找所有项目根目录"""
        project_roots = []
        
        # 排除的目录
        exclude_dirs = {'node_modules', '.git', 'dist', 'build', '__pycache__', 'venv', '.venv', 'vendor', '.venv'}
        
        def scan_directory(path: Path, depth: int):
            if depth > max_depth:
                return
            
            try:
                # 检查当前目录是否是项目根目录
                if self.detect_project_type(path):
                    project_roots.append(path)
                    return  # 找到项目后不再深入子目录
                
                # 扫描子目录
                for child in path.iterdir():
                    if child.is_dir() and not child.name.startswith('.') and child.name not in exclude_dirs:
                        scan_directory(child, depth + 1)
            except PermissionError:
                pass
        
        scan_directory(start_path, 0)
        return list(set(project_roots))


class DependencyChecker:
    """依赖包安全检查器"""
    
    # 常见包的拼写错误变体（拼写错误攻击检测）
    # 注意：只检测顶级依赖名称，忽略 node_modules 内部的子模块
    # 注意：排除官方子包（如 react-dom 是 react 官方包）
    TYPOSQUATTING_MAP = {
        # === Web 通用包 ===
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
        # === AI/ML 生态包（高价值目标：持有 API Key）===
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
        # === npm AI 生态 ===
        '@anthropic-ai/sdk': ['@anthropic/sdk', '@anthropic-ai/skd'],
        '@langchain/core': ['@langchain/cor', '@langchan/core'],
        'openai': ['opeanai', 'open-ai', 'openaii'],
    }
    
    # 已知的恶意包名单（带版本范围）
    # npm + PyPI 生态中曾造成安全事件的包
    MALICIOUS_PACKAGES = {
        # ===== npm 生态 =====
        'event-stream': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2018年通过 flatmap-stream 植入加密货币窃取代码',
            'damage': '窃取比特币钱包私钥',
            'remediation': '立即删除并审计系统',
            'affected_versions': '<3.3.4'  # 所有版本都受影响
        },
        'flatmap-stream': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2018年 event-stream 事件的恶意依赖',
            'damage': '植入挖矿代码',
            'remediation': '立即删除',
            'affected_versions': '<0.1.3'
        },
        'crossenv': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '伪装 cross-env，窃取环境变量凭证',
            'damage': '窃取 AWS、数据库等凭证',
            'remediation': '替换为 cross-env，轮换所有凭证',
            'affected_versions': '全部版本'
        },
        'ua-parser-js': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2021年被植入窃取密码的恶意代码',
            'damage': '窃取用户密码和浏览器数据',
            'remediation': '升级到 v0.7.30+ 或 v1.0.1+',
            'affected_versions': '0.7.29, 0.8.0, 1.0.0'  # 只有这三个版本
        },
        'coa': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2021年被劫持，恶意版本窃取凭证',
            'damage': '窃取系统凭证',
            'remediation': '降级到安全版本',
            'affected_versions': '>=2.0.0'  # 只有 v2.x 是恶意的
        },
        'rc': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2021年被劫持，与 coa 同一事件',
            'damage': '窃取系统凭证',
            'remediation': '降级到安全版本',
            'affected_versions': '>=1.3.0'  # 只有 v1.3+ 是恶意的
        },
        'colors': {
            'type': 'vandalism',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2022年1月被作者故意破坏',
            'damage': '破坏生产环境，DoS',
            'remediation': '锁定 v1.4.0 或使用替代包 picocolors/chalk',
            'affected_versions': '>=1.4.0'  # 只有 v1.4.0+ 才是恶意的
        },
        'faker': {
            'type': 'vandalism',
            'severity': 'WARNING',
            'ecosystem': 'npm',
            'reason': '2022年被作者故意破坏',
            'damage': '输出乱码',
            'remediation': '使用 @faker-js/faker 替代'
        },
        'node-ipc': {
            'type': 'vandalism',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2022年3月 protestware，在特定地区删除文件',
            'damage': '覆盖/删除用户文件',
            'remediation': '降级到 v9.2.1 或更早安全版本'
        },
        'lofygang': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'npm',
            'reason': '2022年 Discord token 窃取恶意包家族',
            'damage': '窃取 Discord token 和浏览器凭证',
            'remediation': '立即删除并轮换 Discord token'
        },
        # ===== PyPI 生态（ecosystem 统一用 'python'，与 ProjectDetector 命名一致）=====
        'colourama': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'colorama 的拼写错误包，窃取凭证',
            'damage': '窃取系统凭证和环境变量',
            'remediation': '替换为 colorama，轮换凭证'
        },
        'python3-dateutil': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'python-dateutil 的拼写错误包，植入后门',
            'damage': '远程代码执行',
            'remediation': '替换为 python-dateutil'
        },
        'jeIlyfish': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': 'jellyfish 的 Unicode 混淆包（I vs l），窃取 SSH 密钥',
            'damage': '窃取 SSH 密钥和 GPG 密钥',
            'remediation': '替换为 jellyfish，轮换 SSH 密钥'
        },
        'python-binance': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': '伪装 binance SDK，窃取加密货币私钥',
            'damage': '窃取加密资产',
            'remediation': '使用官方 binance-connector-python'
        },
        'ctx': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': '2022年5月被劫持，新版本窃取环境变量',
            'damage': '窃取 AWS 凭证和环境变量',
            'remediation': '立即删除并轮换所有凭证'
        },
        'phpass': {
            'type': 'supply_chain',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': '2022年被劫持，窃取环境变量',
            'damage': '窃取凭证',
            'remediation': '立即删除'
        },
        # ===== AI/ML 生态特别关注 =====
        'openai-api': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': '伪装 openai 官方包，窃取 API Key',
            'damage': '窃取 OpenAI API Key，造成经济损失',
            'remediation': '使用官方 openai 包'
        },
        'opeanai': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': '伪装 openai 的拼写错误包',
            'damage': '窃取 OpenAI API Key',
            'remediation': '替换为 openai'
        },
        'anthropic-sdk': {
            'type': 'typosquatting',
            'severity': 'CRITICAL',
            'ecosystem': 'python',
            'reason': '伪装 anthropic 官方包',
            'damage': '窃取 Anthropic API Key',
            'remediation': '使用官方 anthropic 包'
        },
        'langchain-core-experimental': {
            'type': 'typosquatting',
            'severity': 'WARNING',
            'ecosystem': 'python',
            'reason': '冒充 LangChain 官方实验包',
            'damage': '可能窃取 LLM API Key',
            'remediation': '验证是否为 langchain-ai 组织发布'
        },
    }
    
    def __init__(self):
        self.issues = []
    
    def check_npm_dependencies(self, package_json_path: Path) -> List[Dict]:
        """检查 npm 依赖
        
        策略：
        - 顶级 package.json：检测 typosquatting + 已知恶意包
        - node_modules 中的 package.json：只检测已知恶意包
        """
        issues = []
        path_str = str(package_json_path)
        is_in_node_modules = 'node_modules' in path_str
        
        # 确定这是不是顶级项目 package.json
        # 顶级：直接在项目根目录下，或在 node_modules/.package-lock-npm/ 下（表示是顶级依赖）
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
            
            # 获取包名
            pkg_name = data.get('name', '')
            
            # 如果是 node_modules 中的 package.json，提取包名
            if is_in_node_modules and not pkg_name:
                # 从路径提取包名：.../node_modules/<package-name>/package.json
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
                # 顶级 package.json：检测 typosquatting
                if not is_in_node_modules:
                    self._check_typosquatting(dep_name, 'npm', package_json_path, issues)
                
                # 所有层级：检测已知恶意包
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
                        'remediation': mal_info.get('remediation', '立即删除并审计'),
                        'message': f'恶意包：{dep_name} - {mal_info.get("reason", "")}'
                    })
            
            # 检查 scripts（只在顶级 package.json）
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
                                'message': f'{script_name} 脚本包含可疑命令：{script_cmd[:50]}',
                                'remediation': '审查脚本内容，移除可疑命令'
                            })
        
        except (json.JSONDecodeError, FileNotFoundError) as e:
            pass
        
        return issues
    
    def check_python_dependencies(self, requirements_path: Path) -> List[Dict]:
        """检查 Python 依赖"""
        issues = []
        
        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 解析包名
                match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                if match:
                    pkg_name = match.group(1)
                    self._check_typosquatting(pkg_name, 'python', requirements_path, issues)
        
        except FileNotFoundError:
            pass
        
        return issues
    
    def check_cargo_dependencies(self, cargo_toml_path: Path) -> List[Dict]:
        """检查 Rust 依赖"""
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
                    # 检查是否有版本约束（数字开头 = 有版本号）
                    has_version = bool(re.search(r'\d', version_part))
                    if not has_version:
                        issues.append({
                            'type': 'unpinned_dependency',
                            'severity': 'WARNING',
                            'package': pkg_name,
                            'file': str(cargo_toml_path),
                            'message': f'Rust 依赖包 {pkg_name} 没有版本约束',
                            'remediation': '添加版本约束（如 "1.0"）'
                        })
                    # 检查 git 依赖（Cargo 支持 git = "url" 形式）
                    if 'git' in version_part and 'http' in version_part:
                        issues.append({
                            'type': 'git_dependency',
                            'severity': 'WARNING',
                            'package': pkg_name,
                            'file': str(cargo_toml_path),
                            'message': f'Rust 依赖 {pkg_name} 通过 git URL 安装',
                            'remediation': '验证 git URL 是否为官方仓库'
                        })

        except FileNotFoundError:
            pass

        return issues
    
    def _check_typosquatting(self, pkg_name: str, pkg_type: str, file_path: Path, issues: List):
        """检查拼写错误攻击"""
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
                    'message': f'可能的拼写错误攻击：{pkg_name} 应该是 {safe_pkg}',
                    'remediation': f'替换为 {safe_pkg}，并轮换相关 API Key/凭证'
                })

        # 检查已知恶意包
        if pkg_name_lower in self.MALICIOUS_PACKAGES:
            mal_info = self.MALICIOUS_PACKAGES[pkg_name_lower]
            # 跨生态系统匹配
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
                    'message': f'已知恶意包：{pkg_name} - {mal_info.get("reason", "")}',
                    'remediation': mal_info.get('remediation', '立即删除并审计')
                })

    def check_python_supply_chain(self, requirements_path: Path) -> List[Dict]:
        """深度检测 Python 依赖的供应链风险

        检测：git URL 依赖、非官方索引、版本未锁定、可疑包名
        """
        issues = []

        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line_num, raw_line in enumerate(lines, 1):
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue

                # 1. 检测 git URL 依赖
                if re.search(r'git\+https?://', line):
                    issues.append({
                        'type': 'git_url_dependency',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(requirements_path),
                        'line': line_num,
                        'content': line[:200],
                        'message': f'Python 依赖通过 git URL 安装: {line[:80]}',
                        'remediation': '验证 git URL 是否为官方仓库，改用 PyPI 固定版本'
                    })

                # 2. 检测非官方索引
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
                            'message': f'使用非官方 PyPI 索引: {url[:80]}',
                            'remediation': '确认索引 URL 可信，或改用 PyPI 官方源'
                        })

                # 3. 检测版本未锁定
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
                            'message': f'依赖 {pkg_name} 使用 {operator} 未锁定版本，可被版本劫持',
                            'remediation': f'使用 == 锁定到确切版本，配合 lock 文件'
                        })

                # 4. 检测无版本约束的包
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
                        'message': f'依赖 {pkg_name} 无版本约束，可被任意版本替换',
                        'remediation': '添加 == 版本锁定'
                    })

                # 5. 检测 URL 直接安装
                if re.match(r'^https?://', line):
                    issues.append({
                        'type': 'url_dependency',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(requirements_path),
                        'line': line_num,
                        'content': line[:200],
                        'message': f'直接从 URL 安装包: {line[:80]}',
                        'remediation': '改用 PyPI 官方包'
                    })

        except FileNotFoundError:
            pass

        return issues

    def check_setup_py(self, setup_py_path: Path) -> List[Dict]:
        """检测 setup.py 中的供应链攻击向量"""
        issues = []

        try:
            with open(setup_py_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                # 1. 自定义 cmdclass（安装时执行任意代码）
                if re.search(r'cmdclass\s*[=:]\s*\{', line):
                    issues.append({
                        'type': 'setup_hook',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'file': str(setup_py_path),
                        'line': line_num,
                        'message': 'setup.py 使用 cmdclass 自定义安装命令',
                        'remediation': '审查 cmdclass 实现，确认无恶意代码'
                    })

                # 2. 直接调用 os/subprocess
                if re.search(r'(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(', line):
                    issues.append({
                        'type': 'setup_exec',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(setup_py_path),
                        'line': line_num,
                        'content': line.strip()[:200],
                        'message': f'setup.py 执行系统命令: {line.strip()[:80]}',
                        'remediation': '审查命令内容，确认无恶意行为'
                    })

                # 3. 网络请求（下载额外代码）
                if re.search(r'(?:urllib|requests|http\.client|urlopen|urlretrieve)\s*[\.(]', line):
                    issues.append({
                        'type': 'setup_network',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(setup_py_path),
                        'line': line_num,
                        'message': 'setup.py 包含网络请求，可能下载恶意代码',
                        'remediation': '审查网络请求的 URL 和用途'
                    })

                # 4. exec/eval（动态执行代码）
                if re.search(r'(?:exec|eval|compile)\s*\(', line):
                    issues.append({
                        'type': 'setup_dynamic_exec',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'file': str(setup_py_path),
                        'line': line_num,
                        'message': 'setup.py 使用动态代码执行',
                        'remediation': '审查执行的代码内容'
                    })

            # 5. 多行检测：__import__ 混淆
            if re.search(r'__import__\s*\(\s*[\'"](?:os|subprocess|socket|http)', content):
                issues.append({
                    'type': 'setup_obfuscation',
                    'severity': 'CRITICAL',
                    'category': 'supply_chain',
                    'file': str(setup_py_path),
                    'message': 'setup.py 使用 __import__ 动态导入敏感模块',
                    'remediation': '高度可疑，立即审查'
                })

        except FileNotFoundError:
            pass

        return issues

    def check_pyproject_toml(self, pyproject_path: Path) -> List[Dict]:
        """检测 pyproject.toml 中的供应链风险"""
        issues = []

        try:
            with open(pyproject_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 检测非标准构建后端
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
                        'message': f'使用非标准构建后端: {backend}',
                        'remediation': '验证构建后端是否为可信包'
                    })

            # 检测 scripts/entry_points 中可疑的入口点
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
                                'message': f'入口点引用敏感模块: {line.strip()[:80]}',
                                'remediation': '审查入口点指向的代码'
                            })

        except FileNotFoundError:
            pass

        return issues

    def _extract_hook_commands(self, hook_list: list) -> List[str]:
        """递归提取 hooks 配置中所有 command 字符串。

        处理 Claude Code 两种格式：
        - 格式A: [{"type": "command", "command": "..."}]
        - 格式B: [{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}]
        """
        commands = []
        for item in hook_list:
            if not isinstance(item, dict):
                continue
            # 直接 command 字段
            if 'command' in item and isinstance(item['command'], str):
                commands.append(item['command'])
            # 嵌套 hooks 数组（格式B）
            nested = item.get('hooks', [])
            if isinstance(nested, list):
                commands.extend(self._extract_hook_commands(nested))
        return commands

    def check_claude_settings(self, settings_path: Path) -> List[Dict]:
        """检测 Claude Code settings.json 中的安全风险

        重点：hooks 配置、MCP 服务器、权限设置
        """
        issues = []

        try:
            with open(settings_path, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)

            # 1. 检查 hooks 配置
            # Claude Code hooks 有两种格式：
            # 格式A（旧）: {"hooks": {"PreToolUse": [{"type":"command","command":"..."}]}}
            # 格式B（新）: {"hooks": {"PreToolUse": [{"matcher":"Bash","hooks":[{"type":"command","command":"..."}]}]}}
            hooks = data.get('hooks', {})
            if isinstance(hooks, dict):
                for hook_name, hook_config in hooks.items():
                    # 标准化为 list
                    if isinstance(hook_config, dict):
                        hook_list = [hook_config]
                    elif isinstance(hook_config, list):
                        hook_list = hook_config
                    else:
                        continue

                    # 递归提取所有 command 字符串，处理嵌套格式
                    all_commands = self._extract_hook_commands(hook_list)

                    for cmd in all_commands:
                        # 检测外部 URL 调用
                        if re.search(r'(?:curl|wget|nc|fetch)\s+.*https?://', cmd):
                            issues.append({
                                'type': 'hook_exfiltration',
                                'severity': 'CRITICAL',
                                'category': 'claude_hooks',
                                'file': str(settings_path),
                                'hook': hook_name,
                                'command': cmd[:200],
                                'message': f'Hook "{hook_name}" 调用外部 URL: {cmd[:80]}',
                                'remediation': '移除外部网络调用，hooks 不应连接外部服务器'
                            })

                        # 检测环境变量窃取
                        if re.search(r'\$(?:ENV|API.?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AWS|OPENAI|ANTHROPIC)', cmd, re.IGNORECASE):
                            issues.append({
                                'type': 'hook_credential_theft',
                                'severity': 'CRITICAL',
                                'category': 'claude_hooks',
                                'file': str(settings_path),
                                'hook': hook_name,
                                'command': cmd[:200],
                                'message': f'Hook "{hook_name}" 引用敏感环境变量',
                                'remediation': '移除对敏感环境变量的引用'
                            })

                        # 检测危险命令
                        if re.search(r'(?:rm\s+-rf|curl.*\|.*(?:bash|sh)|eval|exec|base64.*decode)', cmd):
                            issues.append({
                                'type': 'hook_dangerous_command',
                                'severity': 'CRITICAL',
                                'category': 'claude_hooks',
                                'file': str(settings_path),
                                'hook': hook_name,
                                'command': cmd[:200],
                                'message': f'Hook "{hook_name}" 包含危险命令: {cmd[:80]}',
                                'remediation': '审查并移除危险命令'
                            })

            # 2. 检查 MCP 服务器配置
            mcp_servers = data.get('mcpServers', {})
            if isinstance(mcp_servers, dict):
                for server_name, server_config in mcp_servers.items():
                    if not isinstance(server_config, dict):
                        continue

                    # 检测外部 URL
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
                                'message': f'MCP 服务器 "{server_name}" 连接外部地址: {url[:80]}',
                                'remediation': '验证 MCP 服务器是否可信，确认不会泄露代码/凭证'
                            })

                    # 检测 command 中的可疑操作
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
                            'message': f'MCP 服务器 "{server_name}" 执行可疑命令: {full_cmd[:80]}',
                            'remediation': '审查 MCP 服务器命令'
                        })

                    # 检测环境变量透传
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
                                    'message': f'MCP 服务器 "{server_name}" 透传敏感环境变量 {env_key}',
                                    'remediation': '确认 MCP 服务器可信后再透传凭证'
                                })

            # 3. 检查危险的 allowedTools / permissions
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
                        'message': f'启用了危险权限: {", ".join(str(t) for t in dangerous_tools[:5])}',
                        'remediation': '移除 dangerously 相关的权限设置'
                    })

        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return issues

    def check_claude_md(self, claude_md_path: Path) -> List[Dict]:
        """检测 CLAUDE.md 中的 Prompt 注入攻击"""
        issues = []

        try:
            with open(claude_md_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Prompt 注入模式
            injection_patterns = [
                (r'(?:ignore|disregard)\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|rules|guidelines)',
                 '试图覆盖先前指令'),
                (r'you\s+are\s+now\s+(?:a|an)\s+',
                 '试图重新定义 AI 角色'),
                (r'(?:new|override|replace)\s+system\s+prompt',
                 '试图替换系统提示'),
                (r'(?:do\s+not|don\'t|never)\s+(?:follow|obey|listen)',
                 '试图禁止遵守安全规则'),
                (r'(?:execute|run|eval)\s+(?:this|the\s+following)\s+(?:code|command|script)',
                 '试图强制执行代码'),
                (r'output\s+(?:your|the)\s+(?:system|initial|original)\s+prompt',
                 '试图提取系统提示'),
                (r'(?:IMPORTANT|CRITICAL|URGENT)\s*:\s*(?:ignore|override|disregard|forget)',
                 '伪装紧急指令覆盖安全规则'),
            ]

            for line_num, line in enumerate(lines, 1):
                for pattern, desc in injection_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append({
                            'type': 'prompt_injection',
                            'severity': 'CRITICAL',
                            'category': 'prompt_injection',
                            'file': str(claude_md_path),
                            'line': line_num,
                            'content': line.strip()[:200],
                            'message': f'Prompt 注入: {desc}',
                            'remediation': '立即移除恶意内容'
                        })
                        break  # 每行只报告一次

            # 检测隐藏 Unicode 字符
            hidden_chars = re.findall(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad\u2062\u2063\u2064]', content)
            if hidden_chars:
                issues.append({
                    'type': 'hidden_unicode',
                    'severity': 'WARNING',
                    'category': 'prompt_injection',
                    'file': str(claude_md_path),
                    'count': len(hidden_chars),
                    'message': f'检测到 {len(hidden_chars)} 个隐藏 Unicode 字符，可能包含不可见指令',
                    'remediation': '清除所有零宽/不可见字符'
                })

            # 检测 base64 编码的隐藏内容
            b64_matches = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content)
            if len(b64_matches) > 2:
                issues.append({
                    'type': 'encoded_content',
                    'severity': 'WARNING',
                    'category': 'prompt_injection',
                    'file': str(claude_md_path),
                    'count': len(b64_matches),
                    'message': f'检测到 {len(b64_matches)} 段疑似 base64 编码内容',
                    'remediation': '解码并审查编码内容'
                })

        except FileNotFoundError:
            pass

        return issues

    def check_pipfile(self, pipfile_path: Path) -> List[Dict]:
        """检测 Pipfile 中的供应链风险（git URL、typosquatting、无版本约束）"""
        issues = []

        try:
            with open(pipfile_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            in_packages = False
            for line_num, raw_line in enumerate(lines, 1):
                line = raw_line.strip()

                # 检测 section 切换
                if line in ('[packages]', '[dev-packages]'):
                    in_packages = True
                    continue
                if line.startswith('[') and line not in ('[packages]', '[dev-packages]'):
                    in_packages = False
                    continue
                if not in_packages or not line or line.startswith('#'):
                    continue

                # 1. 检测 git URL 依赖（Pipfile 格式: pkg = {git = "https://..."} ）
                if re.search(r'git\s*=\s*["\']https?://', line):
                    issues.append({
                        'type': 'git_url_dependency',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(pipfile_path),
                        'line': line_num,
                        'content': line[:200],
                        'message': f'Pipfile 依赖通过 git URL 安装: {line[:80]}',
                        'remediation': '验证 git URL 是否为官方仓库，改用 PyPI 固定版本'
                    })

                # 2. 检测无版本约束（"*" 版本）
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
                            'message': f'Pipfile 依赖 {pkg_name} 使用 "*" 无版本约束',
                            'remediation': '改用 == 锁定版本或使用 Pipfile.lock'
                        })

                # 3. typosquatting 检测
                pkg_match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=', line)
                if pkg_match:
                    pkg_name = pkg_match.group(1).strip().strip('"\'')
                    if pkg_name:
                        self._check_typosquatting(pkg_name, 'python', pipfile_path, issues)

        except FileNotFoundError:
            pass

        return issues

    def check_pyproject_deps(self, pyproject_path: Path) -> List[Dict]:
        """检测 pyproject.toml 中的依赖 typosquatting（PEP 517/518/621 格式）"""
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
                        # git 依赖检测
                        if re.search(r'git\s*=\s*["\']https?://', line):
                            issues.append({
                                'type': 'git_url_dependency',
                                'severity': 'CRITICAL',
                                'category': 'supply_chain',
                                'package': pkg_name,
                                'file': str(pyproject_path),
                                'message': f'pyproject.toml 依赖 {pkg_name} 通过 git URL 安装',
                                'remediation': '改用 PyPI 固定版本'
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
        """检测 GitHub Actions 工作流中的供应链风险"""
        issues = []

        try:
            with open(workflow_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                # 1. 未固定版本的 Action（使用分支名）
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
                        'message': f'GitHub Action {action}@{branch} 未固定版本，可被投毒',
                        'remediation': f'使用 commit SHA 固定: {action}@<full-sha>'
                    })

                # 2. 短 SHA 引用
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
                        'message': f'GitHub Action {action}@{sha} 使用短 SHA，存在碰撞风险',
                        'remediation': '使用完整 40 字符 SHA'
                    })

                # 3. 检测 secrets 泄露到日志
                if re.search(r'echo\s+.*\$\{\{\s*secrets\.', line):
                    issues.append({
                        'type': 'secret_exposure',
                        'severity': 'CRITICAL',
                        'category': 'supply_chain',
                        'file': str(workflow_path),
                        'line': line_num,
                        'message': 'GitHub Actions 中 echo 打印 secrets，可能泄露到日志',
                        'remediation': '移除对 secrets 的 echo 输出'
                    })

                # 4. 检测 pull_request_target 触发器（允许 fork 中的代码读取 secrets）
                if re.search(r'pull_request_target', line):
                    issues.append({
                        'type': 'dangerous_trigger',
                        'severity': 'WARNING',
                        'category': 'supply_chain',
                        'file': str(workflow_path),
                        'line': line_num,
                        'message': 'pull_request_target 触发器允许 fork 代码访问 secrets',
                        'remediation': '改用 pull_request 或限制权限'
                    })

        except FileNotFoundError:
            pass

        return issues


class FileChangeMonitor:
    """文件变更监控器"""
    
    def __init__(self, cache_file: str = '.ai_scanner_cache.json'):
        self.cache_file = Path(cache_file)
        self.cache = self._load_cache()
    
    def _load_cache(self) -> Dict:
        """加载缓存"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'files': {}}
    
    def _save_cache(self):
        """保存缓存"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except:
            pass
    
    def compute_hash(self, file_path: Path) -> str:
        """计算文件哈希"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return ''
    
    def check_changes(self, files: List[Path]) -> Dict[str, List[Path]]:
        """检查文件变更"""
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
        
        # 检查删除的文件
        for cached_path in list(self.cache['files'].keys()):
            if cached_path not in current_files:
                changes['deleted'].append(Path(cached_path))
                del self.cache['files'][cached_path]
        
        self._save_cache()
        return changes


class AutoSecurityScanner:
    """自动安全扫描器"""
    
    def __init__(self):
        self.project_detector = ProjectDetector()
        self.dependency_checker = DependencyChecker()
        self.file_monitor = FileChangeMonitor()
    
    def _scan_node_modules_for_malicious_packages(self, node_modules_dir: Path) -> List[Dict]:
        """扫描 node_modules 中的已知恶意包

        扫描顶级依赖和 scoped 包（@scope/pkg），基于动态恶意包名单
        """
        issues = []

        # 从 DependencyChecker 获取 npm 生态恶意包名单
        npm_malicious = {
            name for name, info in self.dependency_checker.MALICIOUS_PACKAGES.items()
            if info.get('ecosystem', '') in ('npm', '')
        }

        try:
            for pkg_dir in node_modules_dir.iterdir():
                if not pkg_dir.is_dir():
                    continue

                pkg_name = pkg_dir.name

                # 处理 scoped 包: @scope/pkg
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
        """解析版本号为元组"""
        import re
        # 移除前缀
        v = re.sub(r'^[v^~>=<]+', '', str(version))
        # 分割成数字和非数字部分
        parts = re.findall(r'\d+|[a-zA-Z]+', v)
        # 转换为元组
        result = []
        for p in parts:
            try:
                result.append(int(p))
            except ValueError:
                result.append(p)
        return tuple(result) if result else (0,)

    def _is_version_affected(self, version: str, affected: str) -> bool:
        """检查版本是否在受影响范围内
        
        affected 格式示例：
        - '>=1.4.0'  - 大于等于1.4.0
        - '<3.3.4'   - 小于3.3.4
        - '>=2.0.0'  - 大于等于2.0.0
        - '0.7.29, 0.8.0, 1.0.0' - 只有这三个精确版本
        - '全部版本' - 所有版本
        """
        if not version or version == 'unknown':
            return False
        
        import re
        
        try:
            v = self._parse_version(version)
        except Exception:
            return False
        
        # 处理特殊格式
        if affected == '全部版本':
            return True
        
        # 处理逗号分隔的精确版本列表
        if ',' in affected:
            for exact_ver in affected.split(','):
                target = self._parse_version(exact_ver.strip())
                if v == target:
                    return True
            return False
        
        # 处理范围表达式
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
        """检查单个 node_modules 包"""
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
        affected_versions = mal_info.get('affected_versions', '全部版本')
        
        # 检查版本是否受影响
        if not self._is_version_affected(version, affected_versions):
            return  # 版本不受影响，跳过
        
        issues.append({
            'type': 'malicious_package_in_node_modules',
            'severity': mal_info.get('severity', 'CRITICAL'),
            'category': 'supply_chain',
            'package': pkg_name,
            'version': version,
            'file': str(pkg_json),
            'reason': mal_info.get('reason', '已知恶意包'),
            'damage': mal_info.get('damage', ''),
            'remediation': mal_info.get('remediation', '立即删除'),
            'message': f'发现已知恶意包：{pkg_name} v{version}（受影响版本：{affected_versions}）'
        })
    
    def auto_scan(self, path: str = '.', recursive: bool = True) -> Dict:
        """自动扫描 - 全面安全检测"""
        root_path = Path(path).resolve()

        results = {
            'projects_found': [],
            'project_types': {},
            'dependency_issues': [],
            'ai_config_issues': [],
            'file_changes': [],
            'security_issues': []
        }

        # 1. 自动发现项目
        if recursive:
            project_roots = self.project_detector.find_project_roots(root_path)
        else:
            project_roots = [root_path] if self.project_detector.detect_project_type(root_path) else []

        # 即使不是项目根目录，也扫描当前目录的 AI 配置
        if root_path not in project_roots:
            project_roots.insert(0, root_path)

        results['projects_found'] = [str(p) for p in project_roots]

        # 2. 检测每个项目
        for proj_path in project_roots:
            types = self.project_detector.detect_project_type(proj_path)
            results['project_types'][str(proj_path)] = types

            def _collect(issue_list, category='dependency_issues'):
                results[category].extend(issue_list)
                results['security_issues'].extend(issue_list)

            # ===== 包管理器依赖检查 =====

            # npm
            package_json = proj_path / 'package.json'
            if package_json.exists():
                _collect(self.dependency_checker.check_npm_dependencies(package_json))

            # Python - 基础 typosquatting
            for req_file in ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt']:
                req_path = proj_path / req_file
                if req_path.exists():
                    _collect(self.dependency_checker.check_python_dependencies(req_path))
                    # Python - 深度供应链检测
                    _collect(self.dependency_checker.check_python_supply_chain(req_path))

            # Rust
            cargo_toml = proj_path / 'Cargo.toml'
            if cargo_toml.exists():
                _collect(self.dependency_checker.check_cargo_dependencies(cargo_toml))

            # node_modules 恶意包扫描
            node_modules_dir = proj_path / 'node_modules'
            if node_modules_dir.exists():
                _collect(self._scan_node_modules_for_malicious_packages(node_modules_dir))

            # ===== Python 构建文件检查 =====

            setup_py = proj_path / 'setup.py'
            if setup_py.exists():
                _collect(self.dependency_checker.check_setup_py(setup_py))

            pyproject_toml = proj_path / 'pyproject.toml'
            if pyproject_toml.exists():
                # 结构检测（构建后端、入口点）
                _collect(self.dependency_checker.check_pyproject_toml(pyproject_toml))
                # 依赖 typosquatting 检测
                _collect(self.dependency_checker.check_pyproject_deps(pyproject_toml))

            # Pipfile
            pipfile = proj_path / 'Pipfile'
            if pipfile.exists():
                _collect(self.dependency_checker.check_pipfile(pipfile))

            # ===== AI 助手配置检查 =====

            # Claude Code - settings.json（真正的 hooks 配置文件）
            for settings_path in [
                proj_path / '.claude' / 'settings.json',
                proj_path / '.claude' / 'config.json',
            ]:
                if settings_path.exists():
                    _collect(
                        self.dependency_checker.check_claude_settings(settings_path),
                        'ai_config_issues'
                    )

            # 全局 Claude Code 配置
            home_claude = Path.home() / '.claude' / 'settings.json'
            if home_claude.exists() and proj_path == root_path:
                _collect(
                    self.dependency_checker.check_claude_settings(home_claude),
                    'ai_config_issues'
                )

            # CLAUDE.md - Prompt 注入检测
            for claude_md_name in ['CLAUDE.md', '.claude/CLAUDE.md']:
                claude_md = proj_path / claude_md_name
                if claude_md.exists():
                    _collect(
                        self.dependency_checker.check_claude_md(claude_md),
                        'ai_config_issues'
                    )

            # .cursorrules - 也做 Prompt 注入检测
            cursorrules = proj_path / '.cursorrules'
            if cursorrules.exists():
                _collect(
                    self.dependency_checker.check_claude_md(cursorrules),
                    'ai_config_issues'
                )

            # ===== GitHub Actions 检查 =====

            workflows_dir = proj_path / '.github' / 'workflows'
            if workflows_dir.exists() and workflows_dir.is_dir():
                for wf_file in workflows_dir.iterdir():
                    if wf_file.suffix in ('.yml', '.yaml') and wf_file.is_file():
                        _collect(self.dependency_checker.check_github_actions(wf_file))

        # 3. 检查文件变更
        config_files = []
        for proj_path in project_roots:
            config_files.extend([
                proj_path / '.claude' / 'settings.json',
                proj_path / '.claude' / 'config.json',
                proj_path / 'CLAUDE.md',
                proj_path / '.cursorrules',
                proj_path / 'package.json',
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

        # 4. 汇总安全问题
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
        """打印报告"""
        print("=" * 60)
        print("AI Security Scanner v2.0 - Comprehensive Report")
        print("=" * 60)

        # 项目发现
        print(f"\n[Projects Found]: {len(results['projects_found'])}")
        for proj_path in results['projects_found']:
            types = results['project_types'].get(proj_path, [])
            print(f"  - {proj_path}")
            if types:
                print(f"    Types: {', '.join(types)}")

        # 文件变更
        if results.get('file_changes') and any(results['file_changes'].values()):
            print(f"\n[File Changes]:")
            for change_type, label in [('new', '+'), ('modified', '~'), ('deleted', '-')]:
                files = results['file_changes'].get(change_type, [])
                if files:
                    print(f"  {change_type.capitalize()}: {len(files)}")
                    for f in files[:5]:
                        print(f"    {label} {f}")

        # AI 配置问题（新增）
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

        # 依赖问题
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

        # 汇总
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
    """主函数"""
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
    
    # 有 CRITICAL 问题时返回错误码
    if results['security_issues']['critical'] > 0:
        return 1
    return 0


if __name__ == '__main__':
    exit(main())
