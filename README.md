📅 2025.09.22

# AI Secret/PII Detector for Python Repos (Azure OpenAI gpt-4o)

## 개요
- GitHub 리포지토리를 **clone** 또는 **로컬 경로**에서 읽어 `.py` 파일을 스캔
- 이 프로젝트는 공개/사내 GitHub 리포지토리를 자동으로 클론하거나 로컬 경로를 받아, 리포지토리 내 .py 파일에서 하드코딩된 API 키, 토큰, 자격증명, 개인정보(PII) 등을 탐지하고 JSON 보고서로 정리하는 스캐너
- **정규식 기반 1차 탐지** 후, **gpt-4o**로 위험 유형 분류 / 요약 / 해결방안 제안
- 결과를 JSON 파일로 정리:
  - `description`, `data_type`, `filename`, `line_number`, `file_path`, `resolution`

---

## 빠른 시작

### 1. Python 3.10+ 설치

### 2. 가상환경 생성 및 활성화
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

### 3. 의존성 설치

```python
pip install -r requirements.txt
```

### 4. Azure OpenAI 설정

Azure AI Foundry에서 gpt-4o를 배포 후, 아래 4개 값 준비:

AZURE_OPENAI_ENDPOINT (예: https://YOUR_RESOURCE_NAME.openai.azure.com)
AZURE_OPENAI_API_KEY
AZURE_OPENAI_DEPLOYMENT_NAME (예: gpt-4o)
AZURE_OPENAI_API_VERSION (기본값: 2024-02-15-preview)
.env 파일 설정 (.env.example 참조)

### 실행 예시

원격 리포지토리 스캔
```BASH
python -m src.cli --repo https://github.com/<user>/<repo>.git --branch main --out report.json
```
로컬 경로 스캔
```BASH
python -m src.cli --local-path /path/to/repo --out report.json
```
LLM 비활성(정규식만 사용)
```BASH
python -m src.cli --repo https://github.com/<user>/<repo>.git --no-llm --out report.json
```

### 출력 예시

```JSON
{
  "issues": [
    {
      "description": "Hardcoded API key found which risks unauthorized access and credential leakage.",
      "data_type": "API Key",
      "filename": "metrics.py",
      "line_number": 29,
      "file_path": "code_sample/metrics.py",
      "resolution": "Remove the hardcoded key, rotate the credential, and load it from environment variables or Azure Key Vault."
    }
  ]
}
```
### 디자인 노트

정규식 패턴: AWS / GitHub / Google / Slack / Password / Private Key, 간단한 PII(Email / Phone / SSN / Credit Card) 포함
False positive 최소화:
LLM에 의심 라인만(단일 라인과 메타데이터) 전달하여 분류/설명을 보강
민감값 자체는 리포트에 저장하지 않음 (LLM 입력도 한 줄로 최소화, 길면 일부 마스킹)
대용량 레포지토리 처리:
--max-findings-per-call로 배치 크기 조절
비밀키/자격증명 해결책:
코드에서 제거하고 .env, CI/CD secret, Azure Key Vault 사용
키 회전(rotate), 로그/에러 메시지에 마스킹

### 참고(공식 문서)
Chat Completions 및 Azure OpenAI Python SDK 사용
gpt-4o 모델 가용성과 배포

### 보안 권장 사항
리포트에 실제 비밀값은 절대 기록하지 않기 (라인 내용은 내부 판단용으로만 사용)
의심 발견 시 즉시 키/토큰 회전 및 접근 권한 재검토
장기적으로는 Secret Scanning(GitHub Advanced Security, Dependabot) 및 DLP와 함께 운용
