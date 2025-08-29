import os
import re
from github import Github

# ---------------- CONFIG ---------------- #
BRANCH_NAME_REGEX = r"^(feature|bug|chore)\/AB#(1?[0-9]{6})-|^((.*?)dependabot\/|sync\/|release\/|hotfix\/|support\/)"
COMMIT_MSG_REGEX = r"^(feat|fix|chore|docs|style|refactor|test|perf)\(AB#\d{6,7}\): .+"
COMMIT_LINE_LENGTH_REGEX = r"^.{1,72}$"

SECURITY_PATTERNS = [
    r"AWS_SECRET_KEY",
    r"-----BEGIN PRIVATE KEY-----",
]

COMPLIANCE_PATTERNS = [
    r"PII",
    r"eval\(",
]

MARKER = "<!-- ai-peer-review -->"  # marker to identify/update existing comment

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

        commit_results.append(
            f"| `{sha}` | {status} | {msg} | {'; '.join(issues) if issues else 'OK'} |"
        )

    result = []
    result.append("### Commit Message Validation\n")
    result.append("| Commit | Status | Message | Notes |")
    result.append("|--------|--------|---------|-------|")
    result.extend(commit_results)

    return "\n".join(result), not invalid_found


def run_security_scan(pr):
    issues = []
    for f in pr.get_files():
        patch = f.patch or ""
        for pattern in SECURITY_PATTERNS:
            if re.search(pattern, patch):
                issues.append(f"Pattern `{pattern}` found in `{f.filename}`")
    return issues


def run_compliance_scan(pr):
    issues = []
    for f in pr.get_files():
        patch = f.patch or ""
        for pattern in COMPLIANCE_PATTERNS:
            if re.search(pattern, patch):
                issues.append(f"Pattern `{pattern}` found in `{f.filename}`")
    return issues


def summarize_pr(pr):
    return f"""
### High-level PR Summary
**Files changed:** {pr.changed_files}  
**Lines added:** {pr.additions}  
**Lines removed:** {pr.deletions}  
"""


def generate_report(pr, branch_msg, commit_validation, security_scan, compliance_scan, branch_status, commit_status, security_status, compliance_status):
    summary_table = [
        "| Check            | Status |",
        "|------------------|--------|",
        f"| Branch Name      | {branch_status} |",
        f"| Commit Messages  | {commit_status} |",
        f"| Security         | {security_status} |",
        f"| Compliance       | {compliance_status} |",
    ]

    report_parts = [
        "\n".join(summary_table),
        "### Branch Name Validation",
        branch_msg,
        summarize_pr(pr),
        commit_validation,
    ]

    # Security
    if security_scan:
        sec_text = "\n".join(f"- {issue}" for issue in security_scan)
        report_parts.append(f"<details>\n<summary>🔒 Security Scan: Issues Found</summary>\n\n{sec_text}\n</details>")
    else:
        report_parts.append("🔒 Security Scan: No issues found ✅")

    # Compliance
    if compliance_scan:
        comp_text = "\n".join(f"- {issue}" for issue in compliance_scan)
        report_parts.append(f"<details>\n<summary>📜 Compliance Scan: Issues Found</summary>\n\n{comp_text}\n</details>")
    else:
        report_parts.append("📜 Compliance Scan: No issues found ✅")

    return MARKER + "\n" + "\n\n".join(report_parts)


# ---------------- MAIN ---------------- #
def main():
    # Get repo/pr info from CLI args or environment
    import sys
    if len(sys.argv) == 4:
        _, repo_name, pr_number, token = sys.argv
    else:
        repo_name = os.getenv("GITHUB_REPOSITORY")
        pr_number = os.getenv("PR_NUMBER")
        token = os.getenv("GITHUB_TOKEN")

        if not (repo_name and pr_number and token):
            print("❌ Missing arguments or environment variables (GITHUB_REPOSITORY, PR_NUMBER, GITHUB_TOKEN)")
            return

    g = Github(token)
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(int(pr_number))

    # Branch name check
    branch_valid, branch_msg = validate_branch_name(pr.head.ref)
    branch_status = "✅" if branch_valid else "❌"

    # Commit messages
    commit_validation, commits_valid = validate_commit_messages(pr)
    commit_status = "✅" if commits_valid else "❌"

    # Security & compliance
    security_issues = run_security_scan(pr)
    compliance_issues = run_compliance_scan(pr)
    security_status = "✅" if not security_issues else "❌"
    compliance_status = "✅" if not compliance_issues else "⚠️"

    # Generate report
    report = generate_report(
        pr, branch_msg, commit_validation,
        security_issues, compliance_issues,
        branch_status, commit_status, security_status, compliance_status
    )

    print(report)

    # Post/update PR comment
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
