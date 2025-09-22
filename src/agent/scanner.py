import os
import re
from typing import List, Dict

# 기본 정규식 패턴(대표적인 API Key/토큰/PII 탐지)
PATTERNS = [
    # API Keys / Tokens
    {"name": "AWS Access Key ID", "regex": r"AKIA[0-9A-Z]{16}", "type": "API Key"},
    {"name": "AWS Secret Access Key", "regex": r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", "type": "API Key"},
    {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "type": "API Key"},
    {"name": "Slack Token", "regex": r"xox[aboprst]-[0-9A-Za-z-]{10,48}", "type": "API Key"},
    {"name": "GitHub Token", "regex": r"gh[pousr]_[A-Za-z0-9]{36,255}", "type": "API Key"},
    {"name": "JWT", "regex": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "type": "Token"},
    {"name": "Azure Storage ConnStr", "regex": r"AccountKey=[^;]+;", "type": "Credentials"},
    {"name": "Private Key Block", "regex": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "type": "Secret"},
    {"name": "Password Assignment", "regex": r"(?i)\b(password|passwd|pwd)\s*=\s*['\"][^'\"\\r\\n]{4,}['\"]", "type": "Credentials"},
    # PII (간단한 패턴 - false positive 가능)
    {"name": "Email Address", "regex": r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+", "type": "Personal Data"},
    {"name": "US SSN", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "type": "Personal Data"},
    {"name": "Credit Card", "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "type": "Personal Data"},
    {"name": "Phone Number", "regex": r"(?:(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{4})", "type": "Personal Data"},
]

EXCLUDE_DIRS = {
    ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".mypy_cache", ".pytest_cache"
}

def _should_skip_dir(path: str) -> bool:
    base = os.path.basename(path)
    return base in EXCLUDE_DIRS

def _is_python_file(path: str) -> bool:
    return path.lower().endswith((".py", ".pyw", ".pyi"))

def scan_repository_for_secrets(root_dir: str) -> List[Dict]:
    findings: List[Dict] = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # skip noisy dirs
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(os.path.join(dirpath, d))]
        for fname in filenames:
            if not _is_python_file(fname):
                continue
            full_path = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(full_path, root_dir)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception as e:
                print(f"[WARN] Failed to read {rel_path}: {e}")
                continue

            for idx, line in enumerate(lines, start=1):
                for pat in PATTERNS:
                    if re.search(pat["regex"], line):
                        findings.append({
                            "pattern_name": pat["name"],
                            "data_type": pat["type"],
                            "filename": fname,
                            "line_number": idx,
                            "file_path": rel_path,
                            # 컨텍스트는 LLM 분류용으로만 사용(레포트에는 비노출)
                            "code_line": line.strip()[:500]
                        })
    return findings
