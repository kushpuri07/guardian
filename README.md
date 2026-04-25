# Guardian

Autonomous security review for pull requests. Guardian monitors your GitHub repositories and, upon the opening of a pull request, deploys a three-agent pipeline that identifies vulnerabilities, proves their existence through exploitation, patches the affected code, and verifies the fix — without any human involvement.

---

## The Problem

Small engineering teams ship insecure code not because they are careless, but because dedicated security expertise is expensive and rarely available at the pull request level. Existing static analysis tools flag potential vulnerabilities but do not prove they are exploitable, do not fix them, and produce output that requires security knowledge to interpret. Guardian addresses all three gaps.

---

## How It Works

Guardian integrates with GitHub via OAuth and installs a webhook on repositories the user chooses to protect. From that point forward, every pull request triggers the agent pipeline automatically. The developer's workflow does not change.

### Trigger

When a pull request is opened or a new commit is pushed to an open pull request, GitHub delivers a webhook event to Guardian's server. The orchestrator receives this event, fetches the pull request diff and the full contents of changed files, filters out non-code assets, and dispatches the three agents.

### Agent A — The Hacker

Agent A receives the diff and the full file contents. It reasons about potential attack vectors, identifies the single highest-impact vulnerability present, and writes a self-contained Python exploit script designed to prove the vulnerability exists. The exploit is executed in an isolated subprocess. If the exploit succeeds, the finding is confirmed as real and is passed to Agent B. If no vulnerability is found or the exploit does not succeed, the pipeline halts and a clean result is posted to the pull request.

### Agent B — The Engineer

Agent B receives the vulnerable file, the confirmed exploit, and the nature of the vulnerability. It rewrites the affected code to eliminate the vulnerability while preserving all existing function signatures, variable names, and logic. The patch is returned as the complete corrected file.

### Agent C — The Reviewer

Agent C verifies the patch by running the original exploit script against the patched code and executing the existing test suite if one is present. If the exploit no longer succeeds and all tests pass, the patch is approved. If either check fails, Agent C constructs a structured error report — including which check failed, the error output, and a diagnostic hint — and sends it back to Agent B for a revised attempt. This retry loop runs up to three times before escalating to a human reviewer.

### Output

Once a patch is approved, Guardian pushes the patched file as a new commit to the pull request branch and updates the pull request comment with a plain-English summary of the finding, the fix, and the commit reference. The comment is written for a developer with no security background.

---

## Pipeline Diagram

```
Pull Request Opened / Updated
            |
            v
     Orchestrator
     - Fetch diff and file contents
     - Filter non-code files
     - Dispatch agents
            |
            v
     Agent A: Hacker
     - Analyze code for vulnerabilities
     - Write proof-of-concept exploit
     - Execute exploit in isolated subprocess
            |
     Exploit succeeded?
     |              |
    No             Yes
     |              |
  Post             v
 "All         Agent B: Engineer
 Clear"       - Receive vulnerable code + exploit
              - Rewrite function securely
              - Return complete patched file
                    |
                    v
             Agent C: Reviewer
             - Run exploit against patched code
             - Run existing test suite
                    |
             Both checks pass?
             |              |
            No             Yes
             |              |
     Retry (max 3)    Push fix commit
     Send error       to PR branch
     context to            |
     Agent B               v
                    Update PR comment
                    with finding and fix
```

---

## Architecture

```
guardian/
├── main.py               # FastAPI application, GitHub OAuth, webhook receiver
├── orchestrator.py       # Agent coordination and pipeline logic
├── memory.py             # Persistent JSON store for findings and state
├── agents/
│   ├── hacker.py         # Agent A: vulnerability detection and exploitation
│   ├── engineer.py       # Agent B: secure code generation
│   └── reviewer.py       # Agent C: verification and retry loop
├── tools/
│   ├── github_tools.py   # GitHub API interactions
│   └── code_runner.py    # Isolated subprocess execution for exploits and tests
└── dashboard/
    ├── index.html         # Landing page with GitHub OAuth entry point
    └── repos.html         # Repository selector and protection management
```

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, uvicorn |
| LLM | Groq API — Llama 3.3 70B |
| GitHub Integration | GitHub OAuth Apps, REST API v3, Webhooks |
| Code Execution | Python subprocess with timeout isolation |
| Persistence | JSON file store |
| Tunnel (development) | ngrok |

---

## Setup

### Prerequisites

- Python 3.11 or higher
- A GitHub account
- A Groq API key (free at console.groq.com)
- ngrok (for local development)

### Installation

```bash
git clone https://github.com/yourname/guardian.git
cd guardian
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Copy the environment template and fill in your credentials:

```bash
cp .env.example .env
```

```
GITHUB_CLIENT_ID=your_github_oauth_app_client_id
GITHUB_CLIENT_SECRET=your_github_oauth_app_client_secret
GITHUB_WEBHOOK_SECRET=your_chosen_webhook_secret
GITHUB_TOKEN=your_github_personal_access_token
GROQ_API_KEY=your_groq_api_key
NGROK_URL=https://your-ngrok-url.ngrok-free.app
```

### GitHub OAuth App

Create a GitHub OAuth App at github.com/settings/developer settings with the following settings:

```
Homepage URL:              http://localhost:8000
Authorization callback URL: http://localhost:8000/auth/callback
```

The personal access token requires the following scopes: `repo` and `admin:repo_hook`.

### Running

```bash
# Start the server
uvicorn main:app --reload --port 8000

# In a separate terminal, start the tunnel
ngrok http 8000
```

Update `NGROK_URL` in `.env` with the URL provided by ngrok, then open `http://localhost:8000`.

---

## Usage

1. Open `http://localhost:8000` and click Connect GitHub
2. Authorize Guardian to access your repositories
3. Select a repository and click Protect
4. Open a pull request on that repository
5. Guardian will automatically analyze the pull request and post its findings as a comment

No configuration files, no command-line setup, and no security knowledge is required after the initial installation.

---

## Agent Design Decisions

**Why three separate agents rather than one prompt**

Separating the offensive reasoning (Agent A), the defensive implementation (Agent B), and the verification judgment (Agent C) into distinct agents with distinct system prompts produces more reliable results than a single prompt attempting all three roles. Each agent can be optimized independently, and the retry loop between Agent C and Agent B creates a feedback mechanism that would not exist in a single-pass approach.

**Why the exploit must succeed before patching begins**

Requiring Agent A to run a working exploit before Agent B is invoked eliminates false positives. A vulnerability that cannot be demonstrated through a working exploit is not confirmed and does not warrant an automated patch. This design decision keeps the signal-to-noise ratio high and builds developer trust in Guardian's findings.

**Why the retry loop is bounded at three attempts**

An unbounded retry loop risks infinite recursion when Agent B repeatedly generates incorrect patches. A limit of three attempts ensures that genuinely complex vulnerabilities are escalated to a human reviewer rather than silently failing or producing incorrect fixes.

---

## Limitations

- Guardian currently analyzes one vulnerability per pull request, prioritizing the highest-severity finding
- The exploit sandbox does not use containerization; exploits run in a subprocess with a timeout
- Session state is stored in memory and does not persist across server restarts
- The pipeline is optimized for Python files; support for other languages depends on the LLM's ability to generate working exploits in those languages
