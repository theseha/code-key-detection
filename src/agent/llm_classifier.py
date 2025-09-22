import os
import json
from typing import List, Dict
from openai import AzureOpenAI

SYSTEM_PROMPT = """You are a security code reviewer. You will receive a list of suspicious code lines detected by regex.
For each item, you must classify the data type, explain the high-level risk (description), and propose a concrete resolution.
Only analyze the provided single-line snippet and metadata. Do NOT invent content not present.

Return a JSON object with this shape:
{
  "issues": [
    {
      "description": "... high-level risk ...",
      "data_type": "API Key | Personal Data | Secret | Credentials | Token | Sensitive data",
      "filename": "...",
      "line_number": 123,
      "file_path": "...",
      "resolution": "... remediation advice ..."
    }
  ]
}

Guidance:
- description: one or two sentences, high-level risk (e.g., credential leakage, unauthorized access, privacy risk).
- data_type: choose the best fitting category.
- resolution: actionable steps such as "remove hardcoded secret, rotate keys, use env vars or Azure Key Vault, mask logs."
- If a match looks like a false positive, still provide a cautious description advising review; don't leave it empty.
- Do not include the secret value itself in the output.
"""

USER_ITEM_TEMPLATE = """- pattern_name: {pattern_name}
- data_type_hint: {data_type}
- filename: {filename}
- line_number: {line_number}
- file_path: {file_path}
- code_line: {code_line}"""

class LLMClassifier:
    def __init__(self, endpoint: str, api_key: str, deployment_name: str, api_version: str = "2024-02-15-preview", timeout: int = 30):
        if not endpoint or not api_key or not deployment_name:
            raise ValueError("Missing Azure OpenAI credentials. Ensure AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT_NAME are set.")
        self.client = AzureOpenAI(
            api_key=api_key,
            api_version=api_version,
            azure_endpoint=endpoint,
            timeout=timeout
        )
        self.deployment_name = deployment_name

    def _batch(self, items: List[Dict], size: int) -> List[List[Dict]]:
        return [items[i:i+size] for i in range(0, len(items), size)]

    def classify_and_enrich(self, findings: List[Dict], max_batch: int = 20) -> List[Dict]:
        if not findings:
            return []

        issues: List[Dict] = []
        for batch in self._batch(findings, max_batch):
            user_payload = "\n\n".join(
                USER_ITEM_TEMPLATE.format(
                    pattern_name=item["pattern_name"],
                    data_type=item.get("data_type", "Sensitive data"),
                    filename=item["filename"],
                    line_number=item["line_number"],
                    file_path=item["file_path"],
                    code_line=self._redact(item.get("code_line", ""))
                ) for item in batch
            )
            try:
                resp = self.client.chat.completions.create(
                    model=self.deployment_name,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Analyze the following findings:\n\n{user_payload}"}
                    ],
                    temperature=0.2,
                    max_tokens=900,
                    # JSON Mode: supported by gpt-4o; if server ignores, we fallback to parse
                    response_format={"type": "json_object"}
                )
                content = resp.choices[0].message.content
                parsed = self._safe_parse_json(content)
                batch_issues = parsed.get("issues", [])
                # 최종 스키마 강제: 필요한 키만 유지
                normalized = []
                for it in batch_issues:
                    normalized.append({
                        "description": it.get("description", "Potential sensitive data found. Please review."),
                        "data_type": it.get("data_type", "Sensitive data"),
                        "filename": it.get("filename"),
                        "line_number": it.get("line_number"),
                        "file_path": it.get("file_path"),
                        "resolution": it.get("resolution", "Remove hardcoded sensitive values and use environment variables or Azure Key Vault.")
                    })
                issues.extend(normalized)
            except Exception as e:
                # 실패 시, 최소한의 결과라도 생성
                for item in batch:
                    issues.append({
                        "description": f"Potential sensitive data detected by pattern [{item['pattern_name']}]. Review and remove hardcoded secrets/PII. (LLM fallback)",
                        "data_type": item.get("data_type", "Sensitive data"),
                        "filename": item["filename"],
                        "line_number": item["line_number"],
                        "file_path": item["file_path"],
                        "resolution": "Remove hardcoded values; rotate exposed credentials; use environment variables or Azure Key Vault."
                    })
        return issues

    def _redact(self, text: str) -> str:
        # 간단한 redact: 따옴표 안에 긴 토큰을 가린다
        # 실제 운용 시 더 철저한 마스킹 로직을 고려
        if len(text) > 220:
            return text[:200] + " ... [REDACTED_TRUNCATED]"
        return text

    def _safe_parse_json(self, s: str) -> Dict:
        try:
            return json.loads(s)
        except Exception:
            # 모델이 JSON mode 무시 시, JSON 추출을 시도
            start = s.find("{")
            end = s.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(s[start:end+1])
                except Exception:
                    return {"issues": []}
            return {"issues": []}
