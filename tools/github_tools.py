import httpx
import base64
import os
from dotenv import load_dotenv

load_dotenv()

# This gets set per-request from the session token
# For the demo flow we use the env token as fallback
DEFAULT_TOKEN = os.getenv("GITHUB_TOKEN", "")


def get_headers(token: str = None):
    t = token or DEFAULT_TOKEN
    return {
        "Authorization": f"token {t}",
        "Accept":        "application/vnd.github.v3+json",
    }


async def get_pr_diff(repo: str, pr_number: int, token: str = None) -> str:
    """Fetch the raw diff for a pull request"""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    async with httpx.AsyncClient() as client:
        r = await client.get(
            url,
            headers={
                **get_headers(token),
                "Accept": "application/vnd.github.v3.diff"
            },
            timeout=30
        )
    return r.text


async def get_pr_files(repo: str, pr_number: int, token: str = None) -> list:
    """Get list of files changed in a PR"""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=get_headers(token), timeout=30)
    return r.json()


async def get_file_content(repo: str, file_path: str, branch: str, token: str = None) -> str:
    """Get the full content of a file from a specific branch"""
    url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={branch}"
    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=get_headers(token), timeout=30)
        data = r.json()

    if "content" not in data:
        return ""

    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


async def post_pr_comment(repo: str, pr_number: int, body: str, token: str = None):
    """Post a comment on a pull request"""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    async with httpx.AsyncClient() as client:
        r = await client.post(
            url,
            headers=get_headers(token),
            json={"body": body},
            timeout=30
        )
    return r.json()


async def push_fix_commit(
    repo:        str,
    branch:      str,
    file_path:   str,
    new_content: str,
    commit_msg:  str = "fix: guardian auto-patch security vulnerability",
    token:       str = None
) -> dict:
    """Push a patched file as a new commit to the PR branch"""
    url = f"https://api.github.com/repos/{repo}/contents/{file_path}"

    # First get the current file SHA (required by GitHub API to update)
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{url}?ref={branch}",
            headers=get_headers(token),
            timeout=30
        )
        file_data = r.json()

    sha = file_data.get("sha")
    if not sha:
        print(f"Could not get SHA for {file_path}")
        return {}

    # Push the updated file
    async with httpx.AsyncClient() as client:
        r = await client.put(
            url,
            headers=get_headers(token),
            json={
                "message": commit_msg,
                "content": base64.b64encode(new_content.encode()).decode(),
                "sha":     sha,
                "branch":  branch,
            },
            timeout=30
        )
    return r.json()


async def set_pr_status(
    repo:    str,
    sha:     str,
    state:   str,   # "pending" | "success" | "failure" | "error"
    description: str,
    token:   str = None
):
    """Set a commit status (shows as check on the PR)"""
    url = f"https://api.github.com/repos/{repo}/statuses/{sha}"
    async with httpx.AsyncClient() as client:
        await client.post(
            url,
            headers=get_headers(token),
            json={
                "state":       state,
                "description": description,
                "context":     "guardian/security-review",
            },
            timeout=30
        )


def format_pr_comment(findings: list) -> str:
    """
    Format the agent findings into a clean, readable PR comment.
    This is what the developer actually sees in GitHub.
    """
    if not findings:
        return (
            "## 🛡️ Guardian Security Review\n\n"
            "✅ **All clear.** No vulnerabilities found in this PR.\n\n"
            "*Analyzed by Guardian — autonomous security review*"
        )

    lines = ["## 🛡️ Guardian Security Review\n"]

    for f in findings:
        severity = f.get("severity", "UNKNOWN").upper()
        emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

        lines.append(f"### {emoji} {f.get('vulnerability_type', 'Vulnerability')} — {severity} SEVERITY")
        lines.append(f"**File:** `{f.get('file', 'unknown')}` · Line {f.get('line', '?')}\n")
        lines.append(f"> {f.get('plain_english', 'A vulnerability was found.')}\n")

        if f.get("fixed"):
            commit = f.get("fix_commit", "")
            commit_ref = f"`{commit[:7]}`" if commit else ""
            lines.append(f"✅ **Auto-patched** {commit_ref} — all tests passing, exploit no longer succeeds.\n")
        else:
            lines.append("⚠️ **Could not auto-patch** — manual review required.\n")

        lines.append("---")

    # Summary line
    fixed   = sum(1 for f in findings if f.get("fixed"))
    unfixed = len(findings) - fixed
    lines.append(
        f"\n*{len(findings)} issue(s) found · "
        f"{fixed} auto-patched · "
        f"{unfixed} need manual review · "
        f"powered by Guardian*"
    )

    return "\n".join(lines)
async def edit_pr_comment(repo: str, comment_id: int, body: str, token: str = None):
    """Edit an existing PR comment"""
    url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
    async with httpx.AsyncClient() as client:
        await client.patch(url, headers=get_headers(token), json={"body": body}, timeout=30)