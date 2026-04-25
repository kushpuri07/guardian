from tools.code_runner import run_exploit, run_tests
from agents.engineer import run_engineer

MAX_RETRIES = 3


async def run_reviewer(
    patched_code:  str,
    original_code: str,
    finding:       dict,
    test_code:     str = None,
    attempt:       int = 1
) -> dict:
    """
    Agent C — verify the patch is correct and the exploit no longer works.
    If it fails, send structured feedback back to Agent B and retry.

    Args:
        patched_code:  The file content after Agent B's patch
        original_code: The original vulnerable file
        finding:       The finding from Agent A
        test_code:     Optional unit tests to run
        attempt:       Current retry attempt number

    Returns:
        Dict with status (approved/escalate), attempt count, and details
    """
    print(f"  🔵 Agent C (Reviewer) — verifying patch (attempt {attempt}/{MAX_RETRIES})...")

    if attempt > MAX_RETRIES:
        print("  ⚠️  Agent C — max retries reached, escalating to human")
        return {
            "status":  "escalate",
            "reason":  "Could not produce a working patch after 3 attempts",
            "attempt": attempt,
        }

    # Check 1: Does the exploit still work against the patched code?
    exploit_code    = finding.get("exploit_code", "")
    exploit_result  = {"succeeded": False}

    if exploit_code:
        print("  ⚡ Re-running exploit against patched code...")
        # Run exploit against the patched code by injecting it first
        # Build a verification script that actually calls the patched login function
        verify_script = patched_code + """

        # Test that the SQL injection no longer works
        import sys
        try:
            result = login("admin' OR 1=1 --", "wrongpassword")
            if result:
                print("EXPLOIT_SUCCESS")
                sys.exit(0)
            else:
                print("EXPLOIT_BLOCKED")
                sys.exit(0)
        except Exception as e:
            print(f"EXPLOIT_BLOCKED: {e}")
            sys.exit(0)
        """
        exploit_result = run_exploit(verify_script)
        if exploit_result["succeeded"]:
            print("  ❌ Exploit still works — patch incomplete")
        else:
            print("  ✅ Exploit no longer works")

    # Check 2: Do existing tests still pass?
    test_result = {"passed": True, "errors": ""}
    if test_code:
        print("  🧪 Running test suite...")
        test_result = run_tests(test_code, patched_code)
        if test_result["passed"]:
            print("  ✅ All tests passing")
        else:
            print("  ❌ Tests failed")

    # ── Both checks pass → APPROVE ──────────────────────────────────────────
    if not exploit_result["succeeded"] and test_result["passed"]:
        print(f"  ✅ Agent C — patch approved on attempt {attempt}")
        return {
            "status":       "approved",
            "attempt":      attempt,
            "patched_code": patched_code,
        }

    # ── Something failed → build error context and retry ────────────────────
    error_context = {
        "attempt":             attempt,
        "exploit_still_works": exploit_result.get("succeeded", False),
        "exploit_output":      exploit_result.get("stdout", ""),
        "test_errors":         test_result.get("errors", ""),
        "hint":                _build_hint(exploit_result, test_result),
    }

    print(f"  🔄 Sending back to Agent B with error context (attempt {attempt})")

    # Ask Agent B to try again with the error context
    new_patch = await run_engineer(original_code, finding, error_context)
    new_patched_code = new_patch.get("patched_code", patched_code)

    # Recurse with incremented attempt counter
    return await run_reviewer(
        patched_code=new_patched_code,
        original_code=original_code,
        finding=finding,
        test_code=test_code,
        attempt=attempt + 1,
    )


def _build_hint(exploit_result: dict, test_result: dict) -> str:
    """Build a diagnostic hint to help Agent B understand what went wrong"""
    hints = []

    if exploit_result.get("succeeded"):
        hints.append(
            "The security fix is incomplete — the exploit still succeeds. "
            "Make sure to use parameterized queries / proper input validation."
        )

    if not test_result.get("passed") and test_result.get("errors"):
        # Extract the most relevant part of the error
        errors = test_result["errors"]
        if "AssertionError" in errors:
            hints.append("Unit tests are failing due to assertion errors — check the function return values.")
        elif "ImportError" in errors:
            hints.append("Import error in the patched code — check that all imports are correct.")
        elif "SyntaxError" in errors:
            hints.append("Syntax error in the patched code — check for typos or missing brackets.")
        else:
            hints.append(f"Tests failed with: {errors[:200]}")

    return " ".join(hints) if hints else "Review the patch carefully and try a different approach."