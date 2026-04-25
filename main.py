import hmac
import hashlib
import json
import asyncio
import os
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import httpx
from dotenv import load_dotenv
from orchestrator import run_guardian

load_dotenv()

app = FastAPI()
app.mount("/static", StaticFiles(directory="dashboard"), name="static")

GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
WEBHOOK_SECRET       = os.getenv("GITHUB_WEBHOOK_SECRET", "guardian_secret_123")

# In-memory store for user sessions (fine for hackathon)
sessions = {}

# ─── Pages ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def landing():
    with open("dashboard/index.html") as f:
        return f.read()

# ─── GitHub OAuth ─────────────────────────────────────────────────────────────

@app.get("/auth/login")
async def github_login():
    """Redirect user to GitHub OAuth"""
    scope = "repo,admin:repo_hook"   # repo access + webhook management
    url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&scope={scope}"
        f"&redirect_uri=http://localhost:8000/auth/callback"
    )
    return RedirectResponse(url)

@app.get("/auth/callback")
async def github_callback(code: str):
    """GitHub redirects here after user approves"""
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            json={
                "client_id":     GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code":          code,
            }
        )
        data = r.json()

    token = data.get("access_token")
    if not token:
        raise HTTPException(status_code=400, detail="GitHub auth failed")

    # Get user info
    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}"}
        )
        user = r.json()

    # Save session (use github user id as session key)
    session_id = str(user["id"])
    sessions[session_id] = {
        "token":    token,
        "username": user["login"],
        "avatar":   user["avatar_url"],
    }

    # Redirect to repo selector with session
    response = RedirectResponse(url=f"/repos?session={session_id}")
    return response

# ─── Repo Selector ────────────────────────────────────────────────────────────

@app.get("/repos")
async def list_repos(session: str):
    """Show user's repos so they can pick which to protect"""
    if session not in sessions:
        return RedirectResponse("/")

    token = sessions[session]["token"]

    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://api.github.com/user/repos?sort=updated&per_page=30",
            headers={"Authorization": f"token {token}"}
        )
        repos = r.json()

    # Serve the repos page (we'll build this in dashboard/repos.html)
    with open("dashboard/repos.html") as f:
        html = f.read()

    # Inject repos data as a script tag
    repos_json = json.dumps([{
        "id":       r["id"],
        "name":     r["full_name"],
        "private":  r["private"],
        "language": r["language"],
        "updated":  r["updated_at"],
    } for r in repos if isinstance(r, dict)])

    html = html.replace(
        "<!-- REPOS_DATA -->",
        f"<script>window.REPOS = {repos_json}; window.SESSION = '{session}';</script>"
    )
    return HTMLResponse(html)

@app.post("/repos/protect")
async def protect_repo(request: Request):
    body = await request.json()
    session_id = body.get("session")
    repo_name  = body.get("repo")

    if session_id not in sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = sessions[session_id]["token"]

    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"https://api.github.com/repos/{repo_name}/hooks",
            headers={"Authorization": f"token {token}"},
            json={
                "name":   "web",
                "active": True,
                "events": ["pull_request"],
                "config": {
                    "url": f"{os.getenv('NGROK_URL')}/webhook",
                    "content_type": "json",
                    "secret":       WEBHOOK_SECRET,
                }
            }
        )
        result = r.json()

    if "id" in result:
        # Save to protected repos file
        try:
            with open("protected_repos.json") as f:
                data = json.load(f)
        except Exception:
            data = {"repos": []}
        if repo_name not in data["repos"]:
            data["repos"].append(repo_name)
        with open("protected_repos.json", "w") as f:
            json.dump(data, f)

        return JSONResponse({"status": "protected", "repo": repo_name})
    else:
        return JSONResponse({"status": "error", "detail": result}, status_code=400)

# ─── GitHub Webhook ───────────────────────────────────────────────────────────

@app.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """GitHub fires this when a PR is opened or updated"""

    # Verify the request is genuinely from GitHub
    signature = request.headers.get("X-Hub-Signature-256", "")
    body       = await request.body()

    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = json.loads(body)
    action  = payload.get("action")

    # Only care about PR opened or new commits pushed to a PR
    if action not in ["opened", "synchronize"]:
        return {"status": "ignored"}

    # Ignore commits pushed by Guardian itself to avoid infinite loop
    sender = payload.get("sender", {}).get("login", "")
    commit_msg = payload.get("pull_request", {}).get("head", {}).get("label", "")
    last_commit = payload.get("after", "")
    pr_title = payload.get("pull_request", {}).get("title", "")
    head_commit_msg = payload.get("pull_request", {}).get("head", {}).get("sha", "")

    # Check if this was triggered by guardian's own commit
    if "guardian" in sender.lower():
        print("  ⏭  Skipping — triggered by Guardian bot")
        return {"status": "ignored"}

    pr     = payload["pull_request"]
    repo   = payload["repository"]["full_name"]
    pr_num = pr["number"]
    branch = pr["head"]["ref"]

    print(f"\n🛡 Guardian activated — {repo} PR #{pr_num} ({action})")

    # Run the agent swarm in the background
    # We respond to GitHub immediately (it expects a fast response)
    background_tasks.add_task(run_guardian, repo, pr_num, branch)

    return {"status": "guardian activated"}

# ─── Status endpoint (for dashboard polling) ──────────────────────────────────

@app.get("/status")
async def get_status():
    """Dashboard polls this to show live activity"""
    try:
        with open("memory.json") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"findings": []}
    

@app.get("/auth/logout")
async def logout(session: str):
    if session in sessions:
        del sessions[session]
    return RedirectResponse("/")
@app.get("/protected-repos")
async def get_protected_repos():
    try:
        with open("protected_repos.json") as f:
            return json.load(f)
    except Exception:
        return {"repos": []}
@app.post("/repos/unprotect")
async def unprotect_repo(request: Request):
    body = await request.json()
    session_id = body.get("session")
    repo_name  = body.get("repo")

    if session_id not in sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = sessions[session_id]["token"]

    # Get all webhooks for the repo and delete Guardian's
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"https://api.github.com/repos/{repo_name}/hooks",
            headers={"Authorization": f"token {token}"}
        )
        hooks = r.json()

    # Find and delete Guardian's webhook
    for hook in hooks:
        if "guardian" in hook.get("config", {}).get("url", ""):
            async with httpx.AsyncClient() as client:
                await client.delete(
                    f"https://api.github.com/repos/{repo_name}/hooks/{hook['id']}",
                    headers={"Authorization": f"token {token}"}
                )

    # Remove from protected_repos.json
    try:
        with open("protected_repos.json") as f:
            data = json.load(f)
        data["repos"] = [r for r in data["repos"] if r != repo_name]
        with open("protected_repos.json", "w") as f:
            json.dump(data, f)
    except Exception:
        pass

    return JSONResponse({"status": "unprotected", "repo": repo_name})