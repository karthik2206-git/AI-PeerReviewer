import os
import re
import requests
from github import Github
import json

# Regex rules
COMMIT_MSG_REGEX = r"^(?P<type>build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test|¯\\_\\(ツ\\)_\/¯)(?P<scope>\(AB#(1?[0-9]{6})\))(?P<breaking>!)?(?P<subject>:\s.*)?|^(?P<merge>Merge \w+)|^(?P<suggestion>Update .+)|^(?P<depbot>(build|chore)\(deps\): (sync|Bump|bump|update|\[Linter\]) \w+)"
BRANCH_NAME_REGEX = r"^(feature|bug|chore)\/AB#(1?[0-9]{6})-|^((.*?)dependabot\/|sync\/|release\/|hotfix\/|support\/)"
COMMIT_LINE_LENGTH_REGEX = r"(^.{0,74}$)|^(Merge .+$)|^((build|chore)\(deps\): (sync|Bump|bump|Update|update).+$)"

# Setup GitHub
token = os.environ["GITHUB_TOKEN"]
repo_name = os.environ["GITHUB_REPOSITORY"]
pr_number = int(os.environ["PR_NUMBER"])
branch_name = os.environ["PR_BRANCH"]
gh = Github(token)
repo = gh.get_repo(repo_name)
pr = repo.get_pull(pr_number)

# Setup Copilot
copilot_token = os.getenv("COPILOT_TOKEN")
copilot_api_url = os.getenv("COPILOT_API_URL", "https://api.githubcopilot.com/v1/ai/review")

def validate_branch_name(branch):
    if not re.match(BRANCH_NAME_REGEX, branch): 
        return f" **Branch name** `{branch}` does not follow naming convention: `{BRANCH_NAME_REGEX}`"
    return None

def validate_commit_messages(pr):
    invalid_commits = []
    length_violations = []
    for commit in pr.get_commits():
        msg = commit.commit.message
        if not re.match(COMMIT_MSG_REGEX, msg):
            invalid_commits.append(msg)
        if not re.match(COMMIT_LINE_LENGTH_REGEX, msg):
            length_violations.append(msg)
    result = []
    if invalid_commits:
        result.append(" **Invalid commit messages** detected:\n" + "\n".join(f"- `{msg}`" for msg in invalid_commits))
    if length_violations:
        result.append(" **Commit message line length violations (<74 chars):**\n" + "\n".join(f"- `{msg}`" for msg in length_violations))
    return "\n\n".join(result) if result else None

def get_pr_diff(pr):
    # Use patch-diff endpoint for better compatibility
    url = f"https://patch-diff.githubusercontent.com/raw/{repo_name}/pull/{pr_number}.diff?token={token}"
    print(f"[DEBUG] Patch Diff URL: {url}")
    response = requests.get(url)
    print(f"[DEBUG] Response status code: {response.status_code}")
    if response.status_code != 200:
        print(f"[DEBUG] Response text: {response.text}")
    return response.text if response.status_code == 200 else None



# Automated Security Checks
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
        return " **Potential secrets/credentials detected:**\n" + "\n".join(f"- `{match}`" for match in findings)
    return None

# Compliance & Policy Enforcement
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
            findings.append(f"Keyword `{keyword}` found in diff (check for proper handling)")
    for pattern in risky_patterns:
        if re.search(pattern, diff_text):
            findings.append(f"Risky pattern `{pattern}` found in diff (review for compliance)")
    if findings:
        return " **Compliance/Policy concerns detected:**\n" + "\n".join(f"- {msg}" for msg in findings)
    return None

    # Copilot review function (commented out)
    # def review_code_with_copilot(diff_text):
    #     try:
    #         prompt = f"""
    # You are a senior DevOps + Security engineer reviewing a pull request for a healthcare company.
    # Please review the following code diff for:
    #
    # 1. Code quality, performance, or logic issues
    # 2. Secrets or credential leaks (e.g., API keys, tokens, passwords)
    # 3. Sensitive data handling (e.g., patient data, PII, PHI)
    # 4. Compliance concerns (HIPAA, hardcoded sensitive info)
    #
    # Respond in markdown format with clear findings and suggestions.
    #
    # Code Diff:
    # {diff_text}
    # """
    #         headers = {
    #             "Authorization": f"Bearer {copilot_token}",
    #             "Content-Type": "application/json"
    #         }
    #         payload = {
    #             "prompt": prompt,
    #             "max_tokens": 1000,
    #             "temperature": 0.2
    #         }
    #         response = requests.post(copilot_api_url, headers=headers, data=json.dumps(payload))
    #         if response.status_code == 200:
    #             result = response.json()
    #             content = result.get("choices", [{}])[0].get("message", {}).get("content", "No response from Copilot.")
    #             return " **AI Code Review:**\n" + content
    #         else:
    #             return f" Failed to connect to Copilot: {response.status_code} {response.text}"
    #     except Exception as e:
    #         return f" Failed to connect to Copilot: {e}"


import requests


def summarize_pr_changes(diff_text):
    """
    Returns a high-level summary of changes in the PR diff.
    """
    added = len(re.findall(r'^\+[^+]', diff_text, re.MULTILINE))
    removed = len(re.findall(r'^-[^-]', diff_text, re.MULTILINE))
    files_changed = len(re.findall(r'diff --git', diff_text))
    summary = [
        f"**Files changed:** {files_changed}",
        f"**Lines added:** {added}",
        f"**Lines removed:** {removed}"
    ]
    return "\n".join(summary)

## To use in main():
## summary = summarize_pr_changes(diff_text)
## issues.append('### High-level PR Summary\n' + summary)
# Example usage
# diff = "your PR diff here"
# review_code_with_llm(diff)
        
def post_comment(pr, body):
    pr.create_issue_comment(body)

def main():
    issues = []
    summary_table = [
        '| Check            | Status   |',
        '|------------------|----------|'
    ]
    branch_status = ' Pass'
    commit_status = ' Pass'
    security_status = ' Pass'
    compliance_status = ' Pass'

    # Check branch name
    branch_issue = validate_branch_name(branch_name)
    if branch_issue:
        issues.append(f"### Branch Name Validation\n{branch_issue}")
        branch_status = ' Fail'

    # Check commit messages
    commit_issue = validate_commit_messages(pr)
    if commit_issue:
        issues.append(f"### Commit Message Validation\n{commit_issue}")
        commit_status = ' Fail'

    # AI Review & Security/Compliance Checks
    diff_text = get_pr_diff(pr)
    if diff_text:
        # High-level PR summary
        summary = summarize_pr_changes(diff_text)
        issues.append('### High-level PR Summary\n' + summary)
        # Security checks
        secret_issue = scan_for_secrets(diff_text)
        if secret_issue:
            issues.append('<details>\n<summary> **Security Scan: Issues Found**</summary>\n' + secret_issue + '\n</details>')
            security_status = ' Fail'
        else:
            issues.append('<details>\n<summary> **Security Scan: No Issues**</summary>\nNo secrets or credentials detected.\n</details>')
        # Compliance checks
        compliance_issue = scan_for_compliance(diff_text)
        if compliance_issue:
            issues.append('<details>\n<summary> **Compliance Scan: Issues Found**</summary>\n' + compliance_issue + '\n</details>')
            compliance_status = ' Warn'
        else:
            issues.append('<details>\n<summary> **Compliance Scan: No Issues**</summary>\nNo compliance issues detected.\n</details>')
        # # AI review
        # ai_review = review_code_with_copilot(diff_text)
        # issues.append(ai_review)
    else:
        issues.append("### PR Diff Error\n Could not fetch PR diff. Please check if the PR is accessible and the token is valid.")
        security_status = ' Fail'
        compliance_status = ' Fail'

    # Add summary table at the top
    summary_table.append(f'| Branch Name      | {branch_status} |')
    summary_table.append(f'| Commit Messages  | {commit_status} |')
    summary_table.append(f'| Security         | {security_status} |')
    summary_table.append(f'| Compliance       | {compliance_status} |')
    final_comment = "\n".join(summary_table) + "\n\n" + "\n\n".join(issues)
    post_comment(pr, final_comment)

if __name__ == "__main__":
    main()
