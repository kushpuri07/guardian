import subprocess
import tempfile
import os
import sys
import shutil


def detect_language(exploit_code: str) -> str:
    """
    Detect whether the exploit is Python or JavaScript
    based on common patterns in the code.
    """
    js_patterns = [
        "require(", "const ", "let ", "var ",
        "console.log", "=>", "async function",
        "module.exports", "process.exit"
    ]
    js_score = sum(1 for p in js_patterns if p in exploit_code)
    return "javascript" if js_score >= 2 else "python"


def get_node_path() -> str:
    """Find the Node.js executable path."""
    node = shutil.which("node")
    if node:
        return node
    # Common paths
    for path in ["/usr/bin/node", "/usr/local/bin/node", "/opt/homebrew/bin/node"]:
        if os.path.exists(path):
            return path
    return "node"


def run_exploit(exploit_code: str, timeout: int = 10) -> dict:
    """
    Safely run an exploit script in an isolated subprocess.
    Supports both Python and JavaScript exploits.
    Returns whether it succeeded and any output.
    """
    language = detect_language(exploit_code)
    suffix   = ".js" if language == "javascript" else ".py"

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix,
        delete=False,
        prefix="guardian_exploit_"
    ) as f:
        f.write(exploit_code)
        tmp_path = f.name

    try:
        if language == "javascript":
            runner = [get_node_path(), tmp_path]
            print(f"  🟨 Running JavaScript exploit with Node.js...")
        else:
            runner = [sys.executable, tmp_path]
            print(f"  🐍 Running Python exploit...")

        result = subprocess.run(
            runner,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        succeeded = result.returncode == 0 and "EXPLOIT_SUCCESS" in stdout

        return {
            "succeeded":  succeeded,
            "stdout":     stdout,
            "stderr":     stderr,
            "returncode": result.returncode,
            "language":   language,
        }

    except subprocess.TimeoutExpired:
        return {
            "succeeded":  False,
            "stdout":     "",
            "stderr":     "Exploit timed out",
            "returncode": -1,
            "language":   language,
        }
    except Exception as e:
        return {
            "succeeded":  False,
            "stdout":     "",
            "stderr":     str(e),
            "returncode": -1,
            "language":   language,
        }
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def run_tests(test_code: str, patched_code: str, timeout: int = 15) -> dict:
    """
    Run unit tests against patched code.
    Supports Python (pytest) and JavaScript (Node.js assert).
    """
    language = detect_language(patched_code)

    if language == "javascript":
        return _run_js_tests(test_code, patched_code, timeout)
    else:
        return _run_python_tests(test_code, patched_code, timeout)


def _run_python_tests(test_code: str, patched_code: str, timeout: int) -> dict:
    """Run Python tests using pytest."""
    with tempfile.TemporaryDirectory(prefix="guardian_test_") as tmpdir:
        module_path = os.path.join(tmpdir, "module.py")
        test_path   = os.path.join(tmpdir, "test_module.py")

        with open(module_path, "w") as f:
            f.write(patched_code)

        with open(test_path, "w") as f:
            f.write(test_code)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", test_path, "-v", "--tb=short"],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir,
            )
            passed = result.returncode == 0
            return {
                "passed": passed,
                "output": result.stdout + result.stderr,
                "errors": result.stderr if not passed else "",
            }
        except subprocess.TimeoutExpired:
            return {"passed": False, "output": "Tests timed out", "errors": "Timeout"}
        except Exception as e:
            return {"passed": False, "output": str(e), "errors": str(e)}


def _run_js_tests(test_code: str, patched_code: str, timeout: int) -> dict:
    """Run JavaScript tests using Node.js assert module."""
    with tempfile.TemporaryDirectory(prefix="guardian_test_") as tmpdir:
        module_path = os.path.join(tmpdir, "module.js")
        test_path   = os.path.join(tmpdir, "test_module.js")

        with open(module_path, "w") as f:
            f.write(patched_code)

        # Wrap test code to import the module
        wrapped_test = f"""
const assert = require('assert');
const module = require('./module.js');

try {{
    {test_code}
    console.log('ALL TESTS PASSED');
    process.exit(0);
}} catch(e) {{
    console.error('TEST FAILED:', e.message);
    process.exit(1);
}}
"""
        with open(test_path, "w") as f:
            f.write(wrapped_test)

        try:
            result = subprocess.run(
                [get_node_path(), test_path],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir,
            )
            passed = result.returncode == 0
            return {
                "passed": passed,
                "output": result.stdout + result.stderr,
                "errors": result.stderr if not passed else "",
            }
        except subprocess.TimeoutExpired:
            return {"passed": False, "output": "Tests timed out", "errors": "Timeout"}
        except Exception as e:
            return {"passed": False, "output": str(e), "errors": str(e)}