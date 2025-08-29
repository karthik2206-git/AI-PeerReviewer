import re
import sys
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

# ---------------- HELPERS ---------------- #
def validate_branch_name(branch_name):
    if not re.match(BRANCH_NAME_REGEX, branch_name):
        return False, f"Branch name `{branch_name}` does not follow naming convention: `{BRANCH_NAME_REGEX}`"
    return True, "Branch name is valid ✅"


def validate_commit_messages(pr):
    commit_results = []
    for commit in pr.get_commits():
        sha = commit.sha[:7]
        msg = commit.commit.message.splitlines()[0].strip()

        issues = []
        status = "✅"

        if not re.match(COMMIT_MSG_REGEX, msg):
            issues.append("Invalid format")
            status = "❌"

        if not re.match(COMMIT_LINE_LENGTH_REGEX, msg):
            issues.append("Too long")
            if status == "✅":
                status = "⚠️"

        commit_results.append(
            f"| `{sha}` | {status} | {msg} | {'; '.join(issues) if issues else 'OK'} |"
        )

    result = []
    result.append("### Commit Message Validation\n")
    result.append("| Commit | Status | Message | Notes |")
    result.append("|--------|--------|---------|-------|")
    result.extend(commit_results)

    return "\n".join(result)


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


# ---------------- MAIN ---------------- #
def main(repo_name, pr_number, token):
    g = Github(token)
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(int(pr_number))

    # Branch name
    branch_valid, branch_msg = validate_branch_name(pr.head.ref)

    # Commit messages
    commit_validation = validate_commit_messages(pr)

    # Security + compliance scans
    security_issues = run_security_scan(pr)
    compliance_issues = run_compliance_scan(pr)

    # Statuses
    branch_status = "✅" if branch_valid else "❌"
    commit_status = "✅" if "Invalid format" not in commit_validation and "Too long" not in commit_validation else "❌"
    security_status = "✅" if not security_issues else "❌"
    compliance_status = "✅" if not compliance_issues else "⚠️"

    # Summary table
    summary_table = [
        "| Check            | Status |",
        "|------------------|--------|",
        f"| Branch Name      | {branch_status} |",
        f"| Commit Messages  | {commit_status} |",
        f"| Security         | {security_status} |",
        f"| Compliance       | {compliance_status} |",
    ]

    # Final report
    print("\n".join(summary_table))
    print("\n### Branch Name Validation")
    print(branch_msg)

    print(summarize_pr(pr))
    print(commit_validation)

    if security_issues:
        print("\n<details>\n<summary>🔒 Security Scan: Issues Found</summary>\n")
        for issue in security_issues:
            print(f"- {issue}")
        print("</details>")
    else:
        print("\n🔒 Security Scan: No issues found ✅")

    if compliance_issues:
        print("\n<details>\n<summary>📜 Compliance Scan: Issues Found</summary>\n")
        for issue in compliance_issues:
            print(f"- {issue}")
        print("</details>")
    else:
        print("\n📜 Compliance Scan: No issues found ✅")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python pr_reviewer.py <repo> <pr_number> <github_token>")
        sys.exit(1)
    _, repo_name, pr_number, token = sys.argv
    main(repo_name, pr_number, token)
