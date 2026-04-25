import json
import os

MEMORY_FILE = "memory.json"


def load_memory() -> dict:
    """Load the memory store"""
    if not os.path.exists(MEMORY_FILE):
        return {"findings": []}
    try:
        with open(MEMORY_FILE) as f:
            return json.load(f)
    except Exception:
        return {"findings": []}


def save_finding(finding: dict):
    """Append a new finding to memory"""
    memory = load_memory()
    memory["findings"].append(finding)
    # Keep only the last 100 findings
    memory["findings"] = memory["findings"][-100:]
    with open(MEMORY_FILE, "w") as f:
        json.dump(memory, f, indent=2)


def get_past_findings(repo: str) -> list:
    """Get all past findings for a specific repo"""
    memory = load_memory()
    return [
        f for f in memory["findings"]
        if f.get("repo") == repo
    ]