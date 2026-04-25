import subprocess
import tempfile
import os
import sys


def run_exploit(exploit_code: str, timeout: int = 10) -> dict:
    """
    Safely run an exploit script in an isolated subprocess.
    Returns whether it succeeded and any output.
    """
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        delete=False,
        prefix="guardian_exploit_"
    ) as f:
        f.write(exploit_code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        succeeded = result.returncode == 0 and "EXPLOIT_SUCCESS" in stdout

        return {
            "succeeded": succeeded,
            "stdout":    stdout,
            "stderr":    stderr,
            "returncode": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {
            "succeeded":  False,
            "stdout":     "",
            "stderr":     "Exploit timed out",
            "returncode": -1,
        }
    except Exception as e:
        return {
            "succeeded":  False,
            "stdout":     "",
            "stderr":     str(e),
            "returncode": -1,
        }
    finally:
        # Always clean up the temp file
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def run_tests(test_code: str, patched_code: str, timeout: int = 15) -> dict:
    """
    Run unit tests against patched code.
    Writes both files to temp dir and runs pytest.
    """
    with tempfile.TemporaryDirectory(prefix="guardian_test_") as tmpdir:
        # Write the patched module
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
                "passed":  passed,
                "output":  result.stdout + result.stderr,
                "errors":  result.stderr if not passed else "",
            }

        except subprocess.TimeoutExpired:
            return {
                "passed": False,
                "output": "Tests timed out",
                "errors": "Tests timed out after 15 seconds",
            }
        except Exception as e:
            return {
                "passed": False,
                "output": str(e),
                "errors": str(e),
            }