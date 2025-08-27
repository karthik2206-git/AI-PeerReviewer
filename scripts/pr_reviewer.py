import os
import re
import requests
from github import Github
import openai

# Regex rules
COMMIT_MSG_REGEX = r"^(feat|fix|docs|style|refactor|test|chore): .{10,}$"
BRANCH_NAME_REGEX = r"^(feature|bugfix|hotfix|release)/[a-z0-9\-_]+$"

# Setup GitHub
token = os.environ["GITHUB_TOKEN"]
repo_name = os.environ["GITHUB_REPOSITORY"]
pr_number = int(os.environ["PR_NUMBER"])
branch_name = os.environ["PR_BRANCH"]
gh = Github(token)
repo = gh.get_repo(repo_name)
pr = repo.get_pull(pr_number)

# Setup OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

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

from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def review_code_with_openai(diff_text):
    try:
        prompt = f"""
You are a senior DevOps + Security engineer reviewing a pull request for a healthcare company.
Please review the following code diff for:

1. Code quality, performance, or logic issues
2. Secrets or credential leaks (e.g., API keys, tokens, passwords)
3. Sensitive data handling (e.g., patient data, PII, PHI)
4. Compliance concerns (HIPAA, hardcoded sensitive info)

Respond in markdown format with clear findings and suggestions.

Code Diff:
"""
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a code reviewer and security expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=1000
        )
        return "🤖 **AI Code Review:**\n" + response.choices[0].message.content
    except Exception as e:
        return f"⚠️ Failed to connect to OpenAI: {e}"
        
def post_comment(pr, body):
    pr.create_issue_comment(body)

def main():
    issues = []

    # Check branch name
    branch_issue = validate_branch_name(branch_name)
    if branch_issue:
        issues.append(branch_issue)

    # Check commit messages
    commit_issue = validate_commit_messages(pr)
    if commit_issue:
        issues.append(commit_issue)

    # AI Review
    diff_text = get_pr_diff(pr)
    if diff_text:
        ai_review = review_code_with_openai(diff_text)
        issues.append(ai_review)
    else:
        issues.append("⚠️ Could not fetch PR diff.")

    # Post result
    final_comment = "\n\n".join(issues)
    post_comment(pr, final_comment)

if __name__ == "__main__":
    main()
