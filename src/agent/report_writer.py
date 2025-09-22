import json
from typing import List, Dict

def write_report(path: str, issues: List[Dict]):
    # 최종 스키마: {"issues": [ ... ]}
    payload = {"issues": issues}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
