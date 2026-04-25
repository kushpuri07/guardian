import os
import json
import re
from groq import Groq

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

ENGINEER_SYSTEM = """You are a senior security engineer fixing vulnerable Python code.

Return ONLY a single line of valid JSON, no markdown, no newlines inside string values:
{"patched_code":"import sqlite3\ndef login(u,p):\n    conn=sqlite3.connect('users.db')\n    r=conn.execute('SELECT * FROM users WHERE username=? AND password=?',(u,p)).fetchone()\n    return r","explanation":"Used parameterized queries to prevent SQL injection"}

CRITICAL:
- patched_code must use \\n for newlines inside the JSON string
- Return the COMPLETE fixed file, not just the changed function
- Use parameterized queries to fix SQL injection
- Preserve all existing function signatures and logic
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

async def run_engineer(original_code, finding, error_context=None):
    print("  🟢 Agent B (Engineer) — patching vulnerable code...")
    prompt = f"""VULNERABLE CODE:
{original_code}

VULNERABILITY: {finding.get('vulnerability_type')} at line {finding.get('line')}
VULNERABLE SNIPPET: {finding.get('vulnerable_code')}
WORKING EXPLOIT: {finding.get('exploit_code', '')}
"""
    if error_context:
        prompt += f"\nPREVIOUS PATCH FAILED — attempt #{error_context.get('attempt',2)}\nHint: {error_context.get('hint','')}\n"

    cleaned = ""
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": ENGINEER_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=3000,
        )
        raw = response.choices[0].message.content.strip()
        print(f"  📝 Raw: {raw[:200]}")
        cleaned = clean_json(raw)
        result = json.loads(cleaned)
        print(f"  🟢 Patch ready: {result.get('explanation','')}")
        return result
    except json.JSONDecodeError as e:
        print(f"  ⚠️  Agent B JSON error: {e}")
        print(f"  📝 Cleaned: {cleaned[:200]}")
        return {"patched_code": original_code, "explanation": str(e)}
    except Exception as e:
        print(f"  ⚠️  Agent B error: {e}")
        return {"patched_code": original_code, "explanation": str(e)}
