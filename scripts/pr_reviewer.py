import os
import re
import subprocess
from github import Github

# ---------------- CONFIG ---------------- #
BRANCH_NAME_REGEX = r"^(feature|bug|chore)\/AB#(1?[0-9]{6})-|^((.*?)dependabot\/|sync\/|release\/|hotfix\/|support\/)"
COMMIT_MSG_REGEX = r"^(feat|fix|chore|docs|style|refactor|test|perf)\(AB#\d{6,7}\):\s?.+"
COMMIT_LINE_LENGTH_REGEX = r"^.{1,72}$"

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


def summarize_pr(pr):
    return f"""
### High-level PR Summary
**Files changed:** {pr.changed_files}  
**Lines added:** {pr.additions}  
**Lines removed:** {pr.deletions}  
"""


# ---------------- GITLEAKS SCAN ---------------- #
def run_gitleaks_scan(repo_path="."):
    """
    Runs gitleaks in filesystem mode for the current branch.
    Returns a list of detected secrets.
    """
    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--source", repo_path, "--report-format", "json"],
            capture_output=True,
            text=True,
            check=False
        )
        output = result.stdout.strip()
        import json
        secrets = []
        if output:
            data = json.loads(output)
            for entry in data:
                path = entry.get("file", "")
                secret_type = entry.get("rule", "")
                secrets.append(f"{secret_type} found in `{path}`")
        return secrets
    except Exception as e:
        return [f"Gitleaks scan failed: {e}"]


# ---------------- REPORT GENERATION ---------------- #
def generate_report(pr, branch_msg, commit_validation, gitleaks_issues,
                    branch_status, commit_status, security_status):
    summary_table = [
        "| Check            | Status |",
        "|------------------|--------|",
        f"| Branch Name      | {branch_status} |",
        f"| Commit Messages  | {commit_status} |",
        f"| Security         | {security_status} |",
    ]

    report_parts = [
        "\n".join(summary_table),
        "### Branch Name Validation",
        branch_msg,
        summarize_pr(pr),
        commit_validation,
    ]

    # Security / Gitleaks
    if gitleaks_issues:
        sec_text = "\n".join(f"- {issue}" for issue in gitleaks_issues)
        report_parts.append(f"<details>\n<summary>🔒 Security Scan: Issues Found</summary>\n\n{sec_text}\n</details>")
    else:
        report_parts.append("🔒 Security Scan: No issues found ✅")

    return MARKER + "\n" + "\n\n".join(report_parts)


# ---------------- MAIN ---------------- #
def main():
    import sys
    import tempfile

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

    # Security scan with Gitleaks
    # Clone PR branch to a temporary folder for scanning
    import git
    temp_dir = tempfile.mkdtemp()
    repo_clone = git.Repo.clone_from(repo.clone_url, temp_dir, branch=pr.head.ref)
    gitleaks_issues = run_gitleaks_scan(temp_dir)
    security_status = "✅" if not gitleaks_issues else "❌"

    # Generate report
    report = generate_report(pr, branch_msg, commit_validation, gitleaks_issues,
                             branch_status, commit_status, security_status)

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
