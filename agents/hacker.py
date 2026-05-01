import os
import json
import re
from groq import Groq
from tools.code_runner import run_exploit

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

HACKER_SYSTEM_PYTHON = """You are a senior penetration tester reviewing a Python file.

Return ONLY a single line of valid JSON, no markdown, no newlines inside values:
{"vulnerability_type":"SQL Injection","severity":"HIGH","plain_english":"An attacker can log in as any user without a password","file":"login.py","line":8,"vulnerable_code":"f string query","exploit_code":"import sqlite3\\nconn=sqlite3.connect(':memory:')\\nconn.execute('CREATE TABLE users(id,username,password,role)')\\nconn.execute(\\\"INSERT INTO users VALUES(1,'admin','secret','admin')\\\")\\nconn.commit()\\nr=conn.execute(\\\"SELECT * FROM users WHERE username='x' OR 1=1 --' AND password='y'\\\").fetchone()\\nif r: print('EXPLOIT_SUCCESS')","found":true}

CRITICAL rules for exploit_code:
- ALWAYS create the database and table from scratch using :memory: — never assume any file exists
- The exploit must be fully self-contained and runnable in isolation
- Must print EXPLOIT_SUCCESS if the attack works
- Use \\n for newlines inside the JSON string
- Write Python exploit code only

If no vulnerability found return exactly: {"found":false}
"""

HACKER_SYSTEM_JAVASCRIPT = """You are a senior penetration tester reviewing a JavaScript/TypeScript file.

Return ONLY a single line of valid JSON, no markdown, no newlines inside values:
{"vulnerability_type":"SQL Injection","severity":"HIGH","plain_english":"An attacker can log in as any user without a password","file":"login.js","line":8,"vulnerable_code":"template literal query","exploit_code":"const assert = require('assert');\\nfunction login(username, password) {\\n  const query = `SELECT * FROM users WHERE username = '${username}'`;\\n  if (query.includes(\\\"' OR 1=1\\\")) { console.log('EXPLOIT_SUCCESS'); }\\n}\\nlogin(\\\"' OR 1=1 --\\\", 'wrong');","found":true}

CRITICAL rules for exploit_code:
- Write JavaScript exploit code that runs with Node.js
- The exploit must be fully self-contained
- Must print EXPLOIT_SUCCESS (using console.log) if the attack works  
- Use \\n for newlines inside the JSON string
- Use process.exit(0) at the end
- Never use require() for non-built-in modules

Focus on these JavaScript vulnerabilities:
- SQL Injection via template literals
- XSS via innerHTML or document.write
- Command injection via exec/spawn with user input
- Hardcoded secrets and API keys
- Insecure eval() usage
- Path traversal in file operations
- Prototype pollution

If no vulnerability found return exactly: {"found":false}
"""

JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}


def detect_file_language(filename: str) -> str:
    """Detect if file is JavaScript or Python based on extension."""
    _, ext = os.path.splitext(filename.lower())
    return "javascript" if ext in JS_EXTENSIONS else "python"


def clean_json(raw):
    raw = re.sub(r"```json|```python|```javascript|```", "", raw).strip()
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
            if char in ('"', '\\', '/', 'n', 'r', 't', 'b', 'f', 'u'):
                result.append(char)
            elif char == "'":
                # \' is invalid JSON — just keep the quote
                result.append("'")
            elif char == '`':
                # \` is invalid JSON — just keep the backtick
                result.append('`')
            elif char == '(':
                # \( is invalid — keep it
                result.append('(')
            elif char == ')':
                result.append(')')
            else:
                # Drop the backslash, keep the char
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

    # Detect language from first file
    first_filename = list(file_contents.keys())[0] if file_contents else "unknown"
    language = detect_file_language(first_filename)
    first_content = list(file_contents.values())[0] if file_contents else diff

    # Pick the right system prompt based on language
    if language == "javascript":
        system_prompt = HACKER_SYSTEM_JAVASCRIPT
        print(f"  🟨 Analyzing as JavaScript/TypeScript...")
    else:
        system_prompt = HACKER_SYSTEM_PYTHON
        print(f"  🐍 Analyzing as Python...")

    cleaned = ""
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this {language} file for vulnerabilities. The filename is: {first_filename}\n\n{first_content}"},
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

    # Run the exploit
    exploit_code = result.get("exploit_code", "")
    if exploit_code:
        print("  ⚡ Running exploit...")
        exploit_result = run_exploit(exploit_code)
        result["exploit_succeeded"] = exploit_result["succeeded"]
        result["exploit_output"]    = exploit_result["stdout"]
        result["language"]          = language
        print(f"  {'💥 SUCCEEDED' if exploit_result['succeeded'] else '❌ failed'}")
        if not exploit_result["succeeded"] and exploit_result.get("stderr"):
            print(f"  📝 Stderr: {exploit_result['stderr'][:200]}")
    else:
        result["exploit_succeeded"] = False
        result["language"]          = language

    return result