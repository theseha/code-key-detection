import argparse
import os
import sys
from dotenv import load_dotenv
from .agent.git_utils import clone_repo
from .agent.scanner import scan_repository_for_secrets
from .agent.llm_classifier import LLMClassifier
from .agent.report_writer import write_report

def main():
    parser = argparse.ArgumentParser(description="Scan a GitHub repo (or local path) for hardcoded secrets/PII in .py files and export a JSON report.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--repo", type=str, help="GitHub repository URL to clone, e.g. https://github.com/owner/repo.git")
    group.add_argument("--local-path", type=str, help="Local folder path of an already cloned repo")
    parser.add_argument("--branch", type=str, default="main", help="Branch to checkout when cloning")
    parser.add_argument("--out", type=str, default="report.json", help="Output JSON report path")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM classification (regex-based only)")
    parser.add_argument("--max-findings-per-call", type=int, default=20, help="Max suspicious lines to pass per LLM call (batching)")
    parser.add_argument("--timeout", type=int, default=30, help="Network timeout seconds for LLM calls")
    args = parser.parse_args()

    load_dotenv()

    if args.repo:
        workdir = os.path.abspath(".tmp")
        os.makedirs(workdir, exist_ok=True)
        local_dir = clone_repo(args.repo, workdir, args.branch)
    else:
        local_dir = os.path.abspath(args.local_path)
        if not os.path.isdir(local_dir):
            print(f"[ERROR] Local path not found: {local_dir}")
            sys.exit(1)

    print(f"[INFO] Scanning repository at: {local_dir}")
    raw_findings = scan_repository_for_secrets(local_dir)

    if args.no_llm:
        issues = []
        for f in raw_findings:
            # naive mapping without LLM
            issues.append({
                "description": f"Potential sensitive data detected by pattern [{f['pattern_name']}]. Review and remove hardcoded secrets/PII.",
                "data_type": f.get("data_type", "Sensitive data"),
                "filename": f["filename"],
                "line_number": f["line_number"],
                "file_path": f["file_path"],
                "resolution": "Remove hardcoded sensitive values. Use environment variables or Azure Key Vault; rotate any exposed credentials."
            })
    else:
        print("[INFO] Classifying findings with Azure OpenAI (gpt-4o)...")
        classifier = LLMClassifier(
            endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_key=os.getenv("AZURE_OPENAI_API_KEY"),
            deployment_name=os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview"),
            timeout=args.timeout
        )
        issues = classifier.classify_and_enrich(raw_findings, max_batch=args.max_findings_per_call)

    write_report(args.out, issues)
    print(f"[INFO] Report written to: {args.out}")
    print("[INFO] Done.")

if __name__ == "__main__":
    main()
