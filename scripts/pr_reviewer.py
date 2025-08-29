import os
import re
import requests
from github import Github
import json

# Regex rules
COMMIT_MSG_REGEX = (
    r"^(?P<type>build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test|¯\\_\\(ツ\\)_\/¯)"
    r"(?P<scope>\(AB#(1?[0-9]{6})\))"
    r"(?P<breaking>!)?"
    r"(?P<subject>:\s.*)?"
    r"|^(?P<merge>Merge \w+)"
    r"|^(?P<suggestion>Update .+)"
    r"|^(?P<depbot>(build|chore)\(deps\): (sync|Bump|bump|update|\[Linter\]) \w+)"
)
BRANCH_NAME_REGEX = (
    r"^(feature|bug|chore)\/AB#(1?[0-9]{6})-|^((.*?)dependabot\/|sync\/|release\/|hotfix\/|support\/)"
)
COMMIT_LINE_LENGTH_REGEX = (
    r"(^.{0,74}$)|^(Merge .+$)|^((build|chore)\(deps\): (sync|Bump|bump|Update|update).+$)"
)

# Setup GitHub
token = os.environ["GITHUB_TOKEN"]
repo_name = os.environ["GITHUB_REPOSITORY"]
pr_number = int(os.environ["PR_NUMBER"])
branch_name = os.environ["PR_BRANCH"]
gh = Github(token)
repo = gh.get_repo(repo_name)
pr = repo.get_pull(pr_number)


def validate_branch_name(branch):
    if not re.match(BRANCH_NAME_REGEX, branch):
        return f"**Branch name** `{branch}` does not follow naming convention: `{BRANCH_NAME_REGEX}`"
    return None


def validate_commit_messages(pr):
    commit_results = []
    invalid_commits = False

    for commit in pr.get_commits():
        sha = commit.sha[:7]
        msg = commit.commit.message.splitlines()[0]  # only first line
        status = "✅"
        notes = []

        if not re.match(COMMIT_MSG_REGEX, msg):
            notes.append("Invalid format")
            status = "❌"
            invalid_commits = True
        if not re.match(COMMIT_LINE_LENGTH_REGEX, msg):
            notes.append("Too long")
            if status == "✅":  # downgrade only if not already ❌
                status = "⚠️"
            invalid_commits = True

        commit_results.append(f"| `{sha}` | {status} | {msg} | {', '.join(notes) if notes else 'OK'} |")

    result = []
    result.append("### Commit Message Validation\n")
    result.append("| Commit   | Status | Message | Notes |")
    result.append("|----------|--------|---------|-------|")
    result.extend(commit_results)

    return "\n".join(result), (not invalid_commits)


def get_pr_diff(pr):
    url = f"https://patch-diff.githubusercontent.com/raw/{repo_name}/pull/{pr_number}.diff?token={token}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    return None


def scan_for_secrets(diff_text):
    secret_patterns = [
        r'(?i)(api[_-]?key|token|secret|password|passwd|pwd)[\s:=]+[\'\"]?[A-Za-z0-9\-_/+=]{8,}',
        r'(?i)aws[_-]?access[_-]?key[\s:=]+[A-Za-z0-9/+=]{16,}',
        r'(?i)aws[_-]?secret[_-]?key[\s:=]+[A-Za-z0-9/+=]{32,}',
        r'(?i)-----BEGIN PRIVATE KEY-----',
        r'(?i)ssh-rsa [A-Za-z0-9+/]{100,}'
    ]
    findings = []
    for pattern in secret_patterns:
        matches = re.findall(pattern, diff_text)
        if matches:
            findings.extend(matches)
    if findings:
        return "### 🔒 Security Scan: Issues Found\n" + "\n".join(f"- `{match}`" for match in findings)
    return "### 🔒 Security Scan: No Issues\nNo secrets or credentials detected."


def scan_for_compliance(diff_text):
    compliance_keywords = [
        r'patient', r'PII', r'PHI', r'HIPAA', r'ssn', r'dob', r'address', r'phone', r'email', r'health', r'medical'
    ]
    risky_patterns = [
        r'print\s*\(', r'logging\.debug', r'logging\.info', r'open\s*\(', r'pickle\.load', r'eval\s*\('
    ]
    findings = []
    for keyword in compliance_keywords:
        if re.search(keyword, diff_text, re.IGNORECASE):
            findings.append(f"Keyword `{keyword}` found (check handling)")
    for pattern in risky_patterns:
        if re.search(pattern, diff_text):
            findings.append(f"Risky pattern `{pattern}` found (review carefully)")
    if findings:
        return "### 📜 Compliance Scan: Issues Found\n" + "\n".join(f"- {msg}" for msg in findings)
    return "### 📜 Compliance Scan: No Issues\nNo compliance issues detected."


def summarize_pr_changes(diff_text):
    added = len(re.findall(r'^\+[^+]', diff_text, re.MULTILINE))
    removed = len(re.findall(r'^-[^-]', diff_text, re.MULTILINE))
    files_changed = len(re.findall(r'diff --git', diff_text))
    return (
        "### High-level PR Summary\n"
        f"**Files changed:** {files_changed}\n"
        f"**Lines added:** {added}\n"
        f"**Lines removed:** {removed}\n"
    )


def post_comment(pr, body):
    pr.create_issue_comment(body)


def main():
    issues = []

    # Branch validation
    branch_issue = validate_branch_name(branch_name)
    branch_status = "✅" if not branch_issue else "❌"
    if branch_issue:
        issues.append("### Branch Name Validation\n" + branch_issue)

    # Commit messages
    commit_section, valid_commits = validate_commit_messages(pr)
    commit_status = "✅" if valid_commits else "❌"
    issues.append(commit_section)

    # PR diff scans
    diff_text = get_pr_diff(pr)
    if diff_text:
        issues.append(summarize_pr_changes(diff_text))

        sec_result = scan_for_secrets(diff_text)
        issues.append(f"<details>\n<summary>🔒 Security Scan</summary>\n\n{sec_result}\n</details>")
        security_status = "✅" if "No Issues" in sec_result else "❌"

        comp_result = scan_for_compliance(diff_text)
        issues.append(f"<details>\n<summary>📜 Compliance Scan</summary>\n\n{comp_result}\n</details>")
        compliance_status = "✅" if "No Issues" in comp_result else "⚠️"
    else:
        issues.append("### PR Diff Error\nCould not fetch PR diff.")
        security_status = "❌"
        compliance_status = "❌"

    # Summary table
    summary_table = [
        "| Check            | Status |",
        "|------------------|--------|",
        f"| Branch Name      | {branch_status} |",
        f"| Commit Messages  | {commit_status} |",
        f"| Security         | {security_status} |",
        f"| Compliance       | {compliance_status} |",
    ]

    final_comment = "\n".join(summary_table) + "\n\n" + "\n\n".join(issues)
    post_comment(pr, final_comment)


if __name__ == "__main__":
    main()
