import json
import os
from datetime import datetime
from tools.github_tools import (
    get_pr_diff,
    get_pr_files,
    get_file_content,
    post_pr_comment,
    edit_pr_comment,
    push_fix_commit,
    format_pr_comment,
)
from agents.hacker   import run_hacker
from agents.engineer import run_engineer
from agents.reviewer import run_reviewer
from memory          import save_finding, load_memory

# File extensions worth scanning (skip assets, configs, docs)
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".php", ".rb", ".go", ".java", ".cs",
    ".cpp", ".c", ".h", ".rs", ".swift",
    ".html", ".htm", ".vue", ".svelte",
}


# Files to always skip
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    "requirements.txt",  "go.sum",    "Cargo.lock",
}


async def run_guardian(repo: str, pr_number: int, branch: str, token: str = None):
    """
    Main orchestrator — coordinates all 3 agents for a given PR.
    Called in the background when a webhook fires.
    """
    print(f"\n{'='*60}")
    print(f"🛡️  GUARDIAN ACTIVATED")
    print(f"   Repo:   {repo}")
    print(f"   PR:     #{pr_number}")
    print(f"   Branch: {branch}")
    print(f"{'='*60}\n")

    findings = []

    try:
        # ── Step 1: Get the PR diff and changed files ────────────────────────
        print("📥 Fetching PR diff...")
        diff  = await get_pr_diff(repo, pr_number, token)
        files = await get_pr_files(repo, pr_number, token)

        # Filter to only scannable files
        scannable = [
            f for f in files
            if _is_scannable(f.get("filename", ""))
        ]

        if not scannable:
            print("ℹ️  No scannable files in this PR — skipping")
            await post_pr_comment(
                repo, pr_number,
                "## 🛡️ Guardian Security Review\n\n✅ No code files to scan in this PR.",
                token
            )
            return

        print(f"📂 Scanning {len(scannable)} file(s): {[f['filename'] for f in scannable]}")

        # ── Step 2: Get full content of changed files ────────────────────────
        file_contents = {}
        for f in scannable:
            filename = f["filename"]
            content  = await get_file_content(repo, filename, branch, token)
            if content:
                file_contents[filename] = content

        # ── Step 3: Post "scanning" comment so dev sees activity immediately ─
        scanning_comment = await post_pr_comment(
            repo, pr_number,
            "## 🛡️ Guardian Security Review\n\n⏳ Scanning for vulnerabilities...",
            token
        )
        comment_id = scanning_comment.get("id")
        print(f"  📝 Comment ID: {comment_id}")

        # ── Step 4: Run Agent A (Hacker) ─────────────────────────────────────
        print("\n--- AGENT A: HACKER ---")
        finding = await run_hacker(diff, file_contents)

        if not finding.get("found") or not finding.get("exploit_succeeded"):
            # No vulnerability found or exploit didn't work — all clear
            print("\n✅ No exploitable vulnerabilities found")
            await edit_pr_comment(repo, comment_id, format_pr_comment([]), token)

            return

        # ── Step 5: Run Agent B (Engineer) ────────────────────────────────────
        print("\n--- AGENT B: ENGINEER ---")
        filename      = finding.get("file")
        original_code = file_contents.get(filename, "")

        patch = await run_engineer(original_code, finding)
        patched_code = patch.get("patched_code", original_code)

        # ── Step 6: Run Agent C (Reviewer) with retry loop ────────────────────
        print("\n--- AGENT C: REVIEWER ---")
        review = await run_reviewer(
            patched_code=patched_code,
            original_code=original_code,
            finding=finding,
        )

        # ── Step 7: If approved, push the fix commit ──────────────────────────
        fix_commit_sha = None
        fixed = review["status"] == "approved"

        if fixed and filename:
            print(f"\n📤 Pushing fix commit to {branch}...")
            commit_result = await push_fix_commit(
                repo=repo,
                branch=branch,
                file_path=filename,
                new_content=review.get("patched_code", patched_code),
                token=token,
            )
            fix_commit_sha = (
                commit_result.get("commit", {}).get("sha", "")[:7]
                if commit_result else ""
            )
            print(f"✅ Fix pushed: {fix_commit_sha}")

        # ── Step 8: Save finding to memory ────────────────────────────────────
        finding_record = {
            **finding,
            "repo":       repo,
            "pr_number":  pr_number,
            "fixed":      fixed,
            "fix_commit": fix_commit_sha,
            "timestamp":  datetime.utcnow().isoformat(),
            "attempts":   review.get("attempt", 1),
        }
        save_finding(finding_record)
        findings.append(finding_record)

        # ── Step 9: Post final PR comment ─────────────────────────────────────
        comment_body = format_pr_comment(findings)
        await edit_pr_comment(repo, comment_id, comment_body, token)


        print(f"\n{'='*60}")
        print(f"✅ GUARDIAN COMPLETE — {len(findings)} finding(s)")
        print(f"{'='*60}\n")

    except Exception as e:
        print(f"\n❌ Guardian error: {e}")
        import traceback
        traceback.print_exc()
        # Post error comment so dev knows something happened
        await post_pr_comment(
            repo, pr_number,
            f"## 🛡️ Guardian Security Review\n\n⚠️ Guardian encountered an error: `{e}`",
            token
        )


async def _update_or_post_comment(repo, pr_number, body, token):
    """Post the final comment (replaces the 'scanning...' placeholder)"""
    await post_pr_comment(repo, pr_number, body, token)


def _is_scannable(filename: str) -> bool:
    """Decide if a file is worth scanning"""
    if os.path.basename(filename) in SKIP_FILES:
        return False
    _, ext = os.path.splitext(filename)
    return ext.lower() in SCANNABLE_EXTENSIONS