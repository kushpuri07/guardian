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

MAX_SCAN_ROUNDS = 5  # Maximum number of vulnerabilities to fix per file


async def run_guardian(repo: str, pr_number: int, branch: str, token: str = None):
    """
    Main orchestrator — coordinates all 3 agents for a given PR.
    Now runs multiple scan rounds until the file is fully clean.
    """
    print(f"\n{'='*60}")
    print(f"🛡️  GUARDIAN ACTIVATED")
    print(f"   Repo:   {repo}")
    print(f"   PR:     #{pr_number}")
    print(f"   Branch: {branch}")
    print(f"{'='*60}\n")

    # Load the token for this specific repo
    try:
        with open("protected_repos.json") as f:
            data = json.load(f)
        for r in data["repos"]:
            if isinstance(r, dict) and r.get("name") == repo:
                token = r.get("token")
                print(f"   Token loaded for {repo}")
                break
    except Exception:
        pass

    all_findings = []

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

        # ── Step 4: Run multi-vulnerability loop per file ─────────────────────
        for f in scannable:
            filename = f["filename"]
            current_code = file_contents.get(filename, "")
            if not current_code:
                continue

            scan_round = 1
            file_findings = []

            while scan_round <= MAX_SCAN_ROUNDS:
                print(f"\n🔍 Scan round {scan_round} on {filename}...")

                # Update file contents with latest patched code
                file_contents[filename] = current_code

                # ── Agent A: Find vulnerability ───────────────────────────
                print("\n--- AGENT A: HACKER ---")
                finding = await run_hacker(diff, file_contents)

                if not finding.get("found") or not finding.get("exploit_succeeded"):
                    print(f"\n✅ No more vulnerabilities found in {filename} after {scan_round - 1} fix(es)")
                    break

                print(f"\n🔴 Round {scan_round}: found {finding.get('vulnerability_type')} in {filename}")

                # ── Agent B: Patch the vulnerability ─────────────────────
                print("\n--- AGENT B: ENGINEER ---")
                patch = await run_engineer(current_code, finding)
                patched_code = patch.get("patched_code", current_code)

                # ── Agent C: Verify the fix ───────────────────────────────
                print("\n--- AGENT C: REVIEWER ---")
                review = await run_reviewer(
                    patched_code=patched_code,
                    original_code=current_code,
                    finding=finding,
                )

                fixed = review["status"] == "approved"

                if fixed:
                    # Update current code to the patched version for next round
                    current_code = review.get("patched_code", patched_code)
                    print(f"✅ Round {scan_round} approved — moving to next scan")
                else:
                    print(f"⚠️  Round {scan_round} escalated to human")

                finding_record = {
                    **finding,
                    "repo":      repo,
                    "pr_number": pr_number,
                    "fixed":     fixed,
                    "fix_commit": None,  # will be set after push
                    "timestamp": datetime.utcnow().isoformat(),
                    "attempts":  review.get("attempt", 1),
                    "round":     scan_round,
                }
                file_findings.append(finding_record)
                scan_round += 1

                # Update PR comment after each round so dev sees progress
                await edit_pr_comment(
                    repo, comment_id,
                    _format_progress_comment(file_findings, scan_round),
                    token
                )

            # ── Push ONE fix commit with all rounds of fixes ──────────────
            fixed_findings = [f for f in file_findings if f.get("fixed")]

            if fixed_findings and current_code != file_contents.get(filename, ""):
                print(f"\n📤 Pushing fix commit to {branch}...")
                commit_result = await push_fix_commit(
                    repo=repo,
                    branch=branch,
                    file_path=filename,
                    new_content=current_code,
                    token=token,
                )
                fix_commit_sha = (
                    commit_result.get("commit", {}).get("sha", "")[:7]
                    if commit_result else ""
                )
                print(f"✅ Fix pushed: {fix_commit_sha}")

                # Attach commit SHA to all fixed findings
                for fr in file_findings:
                    if fr.get("fixed"):
                        fr["fix_commit"] = fix_commit_sha

            # Save all findings from this file
            for fr in file_findings:
                save_finding(fr)
                all_findings.append(fr)

        # ── Step 5: Post final PR comment ────────────────────────────────────
        comment_body = format_pr_comment(all_findings)
        await edit_pr_comment(repo, comment_id, comment_body, token)

        print(f"\n{'='*60}")
        print(f"✅ GUARDIAN COMPLETE — {len(all_findings)} finding(s) across all files")
        print(f"{'='*60}\n")

    except Exception as e:
        print(f"\n❌ Guardian error: {e}")
        import traceback
        traceback.print_exc()
        await post_pr_comment(
            repo, pr_number,
            f"## 🛡️ Guardian Security Review\n\n⚠️ Guardian encountered an error: `{e}`",
            token
        )


def _format_progress_comment(findings: list, current_round: int) -> str:
    """Show progress during multi-round scanning"""
    lines = ["## 🛡️ Guardian Security Review\n"]
    lines.append(f"⏳ Scanning... ({len(findings)} issue(s) found so far, round {current_round} in progress)\n")
    for f in findings:
        severity = f.get("severity", "").upper()
        emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
        status = "✅ Fixed" if f.get("fixed") else "⚠️ Escalated"
        lines.append(f"{emoji} **{f.get('vulnerability_type')}** — Round {f.get('round')} — {status}")
    return "\n".join(lines)


async def _update_or_post_comment(repo, pr_number, body, token):
    """Post the final comment"""
    await post_pr_comment(repo, pr_number, body, token)


def _is_scannable(filename: str) -> bool:
    """Decide if a file is worth scanning"""
    if os.path.basename(filename) in SKIP_FILES:
        return False
    _, ext = os.path.splitext(filename)
    return ext.lower() in SCANNABLE_EXTENSIONS