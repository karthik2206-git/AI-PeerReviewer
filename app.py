import os
import re
import requests
from github import Github

# Constants
COMMIT_MSG_REGEX = r"^(feat|fix|docs|style|refactor|test|chore): .{10,}$"
BRANCH_NAME_REGEX = r"^(feature|bugfix|hotfix|release)/[a-z0-9\-_]+$"

# GitHub setup
token = os.environ["GITHUB_TOKEN"]
repo_name = os.environ["GITHUB_REPOSITORY"]
pr_number = int(os.environ["PR_NUMBER"])
branch_name = os.environ["PR_BRANCH"]

gh = Github(token)
repo = gh.get_repo(repo_name)
pr = repo.get_pull(pr_number)

def validate_branch_name(branch):
    if not re.match(BRANCH_NAME_REGEX, branch):
        return f"❌ **Branch name** `{branch}` does not follow naming convention: `{BRANCH_NAME_REGEX}`"
    return None

def validate_commit_messages(pr):
    invalid_commits = []
    for commit in pr.get_commits():
        if not re.match(COMMIT_MSG_REGEX, commit.commit.message):
            invalid_commits.append(commit.commit.message)
    if invalid_commits:
        return "❌ **Invalid commit messages** detected:\n" + "\n".join(f"- `{msg}`" for msg in invalid_commits)
    return None

def get_pr_diff(pr):
    url = pr.diff_url
    headers = {'Authorization': f'token {token}'}
    response = requests.get(url, headers=headers)
    return response.text if response.status_code == 200 else None

def review_code_with_local_ai(diff_text):
    # Placeholder for your internal LLM model (e.g., Copilot Enterprise or local LLM)
    # Simulate the review for now
    return f"🤖 AI Review (simulated):\nDetected {diff_text.count('+')} additions and {diff_text.count('-')} deletions."

def post_comment(pr, body):
    pr.create_issue_comment(body)

def main():
    issues = []

    # Validate branch name
    branch_issue = validate_branch_name(branch_name)
    if branch_issue:
        issues.append(branch_issue)

    # Validate commit messages
    commit_issue = validate_commit_messages(pr)
    if commit_issue:
        issues.append(commit_issue)

    # Get PR diff
    diff_text = get_pr_diff(pr)
    if diff_text:
        review = review_code_with_local_ai(diff_text)
        issues.append(review)
    else:
        issues.append("⚠️ Could not fetch PR diff.")

    # Combine and post comment
    final_comment = "\n\n".join(issues)
    post_comment(pr, final_comment)

if __name__ == "__main__":
    main()
