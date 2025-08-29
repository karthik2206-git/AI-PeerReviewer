import os
import re
import subprocess
import tempfile
import git
import sys
import json
from github import Github

# ---------------- CONFIG ---------------- #
BRANCH_NAME_REGEX = r"^(feature|bug|chore)(\/AB#\d{6,7})?-"
COMMIT_MSG_REGEX = r"^(feat|fix|chore|docs|style|refactor|test|perf)\(AB#\d{6,7}\):\s?.+"
COMMIT_LINE_LENGTH_REGEX = r"^.{1,72}$"
MARKER = "<!-- ai-peer-review -->"

# Compliance config
COMPLIANCE_KEYWORDS = [r'patient', r'PII', r'PHI', r'HIPAA', r'ssn', r'dob', r'address', r'phone', r'email', r'health', r'medical']
RISKY_PATTERNS = [r'print\s*\(', r'logging\.debug', r'logging\.info', r'open\s*\(', r'pickle\.load', r'eval\s*\(', r'exec\s*\(']

# ---------------- HELPERS ---------------- #
def validate_branch_name(branch_name):
    if not re.match(BRANCH_NAME_REGEX, branch_name):
        return False, f"Branch name `{branch_name}` does not follow naming convention: `{BRANCH_NAME_REGEX}`"
    return True, "Branch name is valid ✅"

def validate_commit_messages(pr):
    commit_results = []
    invalid_found = False
    for commit in pr.get_commits():
        sha = commit.sha[:7]
        msg = commit.commit.message.splitlines()[0].strip()
        issues = []
        status = "✅"
        if not re.match(COMMIT_MSG_REGEX, msg):
            issues.append("Invalid format")
            status = "❌"
            invalid_found = True
        if not re.match(COMMIT_LINE_LENGTH_REGEX, msg):
            issues.append("Too long")
            if status == "✅":
                status = "⚠️"
            invalid_found = True
        commit_results.append(f"| `{sha}` | {status} | {msg} | {'; '.join(issues) if issues else 'OK'} |")
    result = ["### Commit Message Validation\n", "| Commit | Status | Message | Notes |", "|--------|--------|---------|-------|"]
    result.extend(commit_results)
    return "\n".join(result), not invalid_found

def summarize_pr(pr, gitleaks_issues=None, compliance_issues=None):
    summary = f"### High-level PR Summary\n**Files changed:** {pr.changed_files}\n**Lines added:** {pr.additions}\n**Lines removed:** {pr.deletions}\n**Commits:** {pr.commits}\n"
    risky_files = set()
    if gitleaks_issues: risky_files.update(gitleaks_issues.keys())
    if compliance_issues: risky_files.update(compliance_issues.keys())
    if risky_files:
        summary += "**Files triggering security/compliance issues:** " + ", ".join(risky_files) + "\n"
    return summary

# ---------------- SECURITY & COMPLIANCE ---------------- #
def run_gitleaks_scan(repo_path="."):
    file_issues = {}
    try:
        result = subprocess.run(["gitleaks", "detect", "--source", repo_path, "--report-format", "json"],
                                capture_output=True, text=True, check=False)
        if result.stdout.strip():
            data = json.loads(result.stdout)
            for entry in data:
                path = entry.get("file", "")
                if "pr_reviewer.py" in path: continue
                rule = entry.get("rule", "")
                file_issues.setdefault(path, []).append(rule)
        return file_issues
    except Exception as e:
        return {"Gitleaks scan error": [str(e)]}

def run_compliance_scan(repo_path="."):
    file_issues = {}
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.py', '.js', '.txt', '.yaml', '.json')) and file != "pr_reviewer.py":
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f: content = f.read()
                    issues = [f"Keyword `{kw}`" for kw in COMPLIANCE_KEYWORDS if re.search(kw, content, re.IGNORECASE)]
                    issues += [f"Risky pattern `{rp}`" for rp in RISKY_PATTERNS if re.search(rp, content)]
                    if issues: file_issues[path] = issues
                except: continue
    return file_issues

# ---------------- GITHUB SECRET SCANNING ---------------- #
def fetch_github_secret_scan(pr, repo):
    secrets_by_file = {}
    try:
        alerts = repo.get_secret_scanning_alerts(state="open")
        for alert in alerts:
            # Only include files changed in PR if available
            file_path = alert.secret_type or "unknown file"
            secrets_by_file.setdefault(file_path, []).append(alert.secret_type)
        return secrets_by_file
    except Exception as e:
        return {"GitHub Secret Scan Error": [str(e)]}

# ---------------- REPORT ---------------- #
def generate_report(pr, branch_msg, commit_validation, gitleaks_issues, compliance_issues, github_secrets,
                    branch_status, commit_status, security_status, compliance_status):
    summary_table = [
        "| Check            | Status |",
        "|------------------|--------|",
        f"| Branch Name      | {branch_status} |",
        f"| Commit Messages  | {commit_status} |",
        f"| Security         | {security_status} |",
        f"| Compliance       | {compliance_status} |"
    ]
    report_parts = ["\n".join(summary_table), "### Branch Name Validation", branch_msg, summarize_pr(pr, gitleaks_issues, compliance_issues), commit_validation]

    # Gitleaks
    if gitleaks_issues:
        sec_text = "\n".join(f"- `{file}`: {', '.join(issues)}" for file, issues in gitleaks_issues.items())
        report_parts.append(f"<details>\n<summary>🔒 Gitleaks Security Scan: Issues Found</summary>\n{sec_text}\n</details>")
    else:
        report_parts.append("🔒 Gitleaks Security Scan: No issues found ✅")

    # Compliance
    if compliance_issues:
        comp_text = "\n".join(f"- `{file}`: {', '.join(issues)}" for file, issues in compliance_issues.items())
        report_parts.append(f"<details>\n<summary>⚖️ Compliance Scan: Issues Found</summary>\n{comp_text}\n</details>")
    else:
        report_parts.append("⚖️ Compliance Scan: No issues found ✅")

    # GitHub Secret Scanning
    if github_secrets:
        secret_text = "\n".join(f"- `{file}`: {', '.join(types)}" for file, types in github_secrets.items())
        report_parts.append(f"<details>\n<summary>🔑 GitHub Secret Scan: Issues Found</summary>\n{secret_text}\n</details>")
    else:
        report_parts.append("🔑 GitHub Secret Scan: No issues found ✅")

    return MARKER + "\n" + "\n\n".join(report_parts)

# ---------------- MAIN ---------------- #
def main():
    repo_name = os.getenv("GITHUB_REPOSITORY")
    pr_number = os.getenv("PR_NUMBER")
    token = os.getenv("GITHUB_TOKEN")
    if not (repo_name and pr_number and token):
        print("❌ Missing environment variables: GITHUB_REPOSITORY, PR_NUMBER, GITHUB_TOKEN")
        return

    gh = Github(token)
    repo = gh.get_repo(repo_name)
    pr = repo.get_pull(int(pr_number))

    branch_valid, branch_msg = validate_branch_name(pr.head.ref)
    branch_status = "✅" if branch_valid else "❌"

    commit_validation, commits_valid = validate_commit_messages(pr)
    commit_status = "✅" if commits_valid else "❌"

    # Clone PR branch for scanning
    temp_dir = tempfile.mkdtemp()
    git.Repo.clone_from(repo.clone_url, temp_dir, branch=pr.head.ref)

    # Security & compliance
    gitleaks_issues = run_gitleaks_scan(temp_dir)
    compliance_issues = run_compliance_scan(temp_dir)
    security_status = "✅" if not gitleaks_issues else "❌"
    compliance_status = "✅" if not compliance_issues else "⚠️"

    # GitHub Secret Scanning
    github_secrets = fetch_github_secret_scan(pr, repo)

    # Generate report
    report = generate_report(pr, branch_msg, commit_validation, gitleaks_issues, compliance_issues, github_secrets,
                             branch_status, commit_status, security_status, compliance_status)
    print(report)

    # Post or update PR comment
    existing_comment = None
    for comment in pr.get_issue_comments():
        if MARKER in comment.body:
            existing_comment = comment
            break
    if existing_comment:
        existing_comment.edit(report)
        print("🔄 Updated existing PR review comment.")
    else:
        pr.create_issue_comment(report)
        print("📝 Created new PR review comment.")

if __name__ == "__main__":
    main()
