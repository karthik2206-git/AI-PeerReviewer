# AI-PeerReviewer

Automated Pull Request review tool for GitHub that validates:

* Branch name conventions
* Commit message format and length
* Secret scanning (Gitleaks + GitHub Secret Scanning)
* Compliance and risky patterns scanning
* High-level PR summary with affected files
* Updates or creates a PR comment with detailed results

---

## Features

* ✅ Branch & commit validation
* 🔒 Secret scanning using **Gitleaks** and optionally **GitHub Secret Scanning**
* ⚖️ Compliance check for sensitive keywords (PII, PHI, HIPAA) and risky code patterns
* 📝 Collapsible, readable PR comment
* 🔄 Updates existing PR comment instead of creating duplicates
* ❌ Skips scanning of the reviewer script itself to reduce false positives

---

## Requirements

* Python 3.8+
* Git installed
* [Gitleaks](https://github.com/zricethezav/gitleaks) installed and accessible in `$PATH`
* GitHub personal access token with `repo` scope (for private repos)

> **Optional:** GitHub Advanced Security token with `security_events` scope for GitHub Secret Scanning

---

## Environment Variables

| Variable            | Description                                     |
| ------------------- | ----------------------------------------------- |
| `GITHUB_TOKEN`      | GitHub token to authenticate API calls          |
| `GITHUB_REPOSITORY` | Repository in `owner/repo` format               |
| `PR_NUMBER`         | Pull Request number to review                   |
| `PR_BRANCH`         | Branch name of the PR                           |
| `COPILOT_TOKEN`     | Optional, for future AI code review integration |

---

## Usage

Run the script locally:

```bash
python scripts/pr_reviewer.py
```

> The script reads environment variables for configuration. It will clone the PR branch, run scans, and post a comment to the PR.

---

## Security & Compliance Scans

* **Gitleaks:** Detects secrets in code (always runs).
* **GitHub Secret Scan:** Only available for private repos with Advanced Security enabled. Falls back gracefully if unavailable.
* **Compliance check:** Scans code for keywords like `PII`, `PHI`, `HIPAA` and risky patterns like `eval()`, `pickle.load()`, `print()` in production code.

---

## PR Comment Example

```
| Check            | Status |
|------------------|--------|
| Branch Name      | ❌      |
| Commit Messages  | ❌      |
| Security         | ❌      |
| Compliance       | ⚠️      |

### Branch Name Validation
Branch name `feature/EnableAI-PR` does not follow naming convention

### High-level PR Summary
Files changed: 5
Lines added: 150
Lines removed: 40
Files triggering security/compliance issues: text.txt, pr.yaml

### Commit Message Validation
| Commit | Status | Message | Notes |
|--------|--------|---------|-------|
| d5e2167 | ❌ | Update pr_reviewer.py | Invalid format |
| bfadff3 | ✅ | feat(AB#123456): add validation | OK |

<details>
<summary>🔒 Gitleaks Security Scan: Issues Found</summary>
- `text.txt`: Potential Secret
</details>

<details>
<summary>⚖️ Compliance Scan: Issues Found</summary>
- `pr.yaml`: Risky pattern `print(`
</details>

<details>
<summary>🔑 GitHub Secret Scan: Issues Found</summary>
- Info: GitHub Secret Scanning not available for this repo/token
</details>
```

---

## GitHub Actions Integration

Example workflow:

```yaml
name: PR Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  pr-review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR branch
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install PyGithub

      - name: Run PR Reviewer
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          PR_BRANCH: ${{ github.head_ref }}
        run: python scripts/pr_reviewer.py
```

---

## Notes

* The script clones the PR branch to a temporary directory for scanning.
* Skips scanning of the script itself (`pr_reviewer.py`) to reduce false positives.
* If GitHub Secret Scan is unavailable, Gitleaks ensures secrets are still detected.

---


