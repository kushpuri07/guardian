import os
import json
import re
from groq import Groq
from tools.code_runner import run_exploit

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

HACKER_SYSTEM = """You are a senior penetration tester reviewing a code diff.

Return ONLY a single line of valid JSON, no markdown, no newlines inside values:
{"vulnerability_type":"SQL Injection","severity":"HIGH","plain_english":"An attacker can log in as any user without a password","file":"login.py","line":8,"vulnerable_code":"f string query","exploit_code":"import sqlite3\\nconn=sqlite3.connect(':memory:')\\nconn.execute('CREATE TABLE users(id,username,password,role)')\\nconn.execute(\\\"INSERT INTO users VALUES(1,'admin','secret','admin')\\\")\\nconn.commit()\\nr=conn.execute(\\\"SELECT * FROM users WHERE username='x' OR 1=1 --' AND password='y'\\\").fetchone()\\nif r: print('EXPLOIT_SUCCESS')","found":true}

CRITICAL rules for exploit_code:
- ALWAYS create the database and table from scratch using :memory: — never assume any file exists
- The exploit must be fully self-contained and runnable in isolation
- Must print EXPLOIT_SUCCESS if the attack works
- Use \\n for newlines inside the JSON string

If no vulnerability found return exactly: {"found":false}
"""

def clean_json(raw):
    raw = re.sub(r"```json|```python|```", "", raw).strip()
    raw = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', raw)
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    if not match:
        return raw
    raw = match.group(0)
    try:
        json.loads(raw)
        return raw
    except Exception:
        pass
    result = []
    in_string = False
    escape_next = False
    for char in raw:
        if escape_next:
            # Only keep valid JSON escape characters
            if char in ('"', '\\', '/', 'n', 'r', 't', 'b', 'f', 'u'):
                result.append(char)
            elif char == "'":
                # Invalid escape \' — replace with just '
                result.append("'")
            else:
                # Drop invalid escape
                result.append(char)
            escape_next = False
        elif char == '\\':
            result.append(char)
            escape_next = True
        elif char == '"':
            result.append(char)
            in_string = not in_string
        elif in_string and char == '\n':
            result.append('\\n')
        elif in_string and char == '\r':
            result.append('\\r')
        elif in_string and char == '\t':
            result.append('\\t')
        else:
            result.append(char)
    return ''.join(result)

async def run_hacker(diff, file_contents):
    print("  🔴 Agent A (Hacker) — analyzing diff...")
    context = f"PR DIFF:\n{diff}\n\nFULL FILE CONTENTS:\n"
    for filename, content in file_contents.items():
        context += f"\n--- {filename} ---\n{content}\n"
    cleaned = ""
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": HACKER_SYSTEM},
                {"role": "user", "content": f"Analyze this Python file for vulnerabilities. The filename is: {list(file_contents.keys())[0] if file_contents else 'unknown'}\n\n{list(file_contents.values())[0] if file_contents else diff}"},
            ],
            temperature=0.2,
            max_tokens=2000,
        )
        raw = response.choices[0].message.content.strip()
        print(f"  📝 Raw: {raw[:400]}")
        cleaned = clean_json(raw)
        result = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"  ⚠️  JSON error: {e}")
        print(f"  📝 Cleaned: {cleaned[:400]}")
        return {"found": False, "error": str(e)}
    except Exception as e:
        print(f"  ⚠️  Error: {e}")
        return {"found": False, "error": str(e)}
    if not result.get("found", False):
        print("  ✅ Agent A — no vulnerability found")
        return {"found": False}
    print(f"  🔴 Found {result.get('vulnerability_type')} in {result.get('file')}")
    exploit_code = result.get("exploit_code", "")
    if exploit_code:
        print("  ⚡ Running exploit...")
        exploit_result = run_exploit(exploit_code)
        result["exploit_succeeded"] = exploit_result["succeeded"]
        result["exploit_output"] = exploit_result["stdout"]
        print(f"  {'💥 SUCCEEDED' if exploit_result['succeeded'] else '❌ failed'}")
    else:
        result["exploit_succeeded"] = False
    return result
