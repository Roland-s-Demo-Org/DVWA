"""
Unit tests for the exec vulnerability fix in vulnerabilities/exec/source/low.php

This test suite verifies that the shell injection vulnerability has been properly
mitigated by wrapping the dynamic user input with escapeshellarg().
"""

import re
import os


def read_file(filepath):
    """Read and return the contents of a file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def test_exec_low_escapeshellarg_applied():
    """
    Test that escapeshellarg() is applied to the $target variable in both
    Windows and *nix branches of the low.php file.
    """
    filepath = "vulnerabilities/exec/source/low.php"

    # Verify file exists
    assert os.path.exists(filepath), f"File {filepath} does not exist"

    content = read_file(filepath)

    # Test 1: Verify Windows branch has escapeshellarg($target)
    windows_pattern = (
        r"shell_exec\s*\(\s*['\"]ping\s+['\"].*escapeshellarg\s*\(\s*\$target\s*\)"
    )
    assert re.search(
        windows_pattern, content, re.DOTALL
    ), "Windows branch should use escapeshellarg($target)"

    # Test 2: Verify *nix branch has escapeshellarg($target)
    nix_pattern = r"shell_exec\s*\(\s*['\"]ping\s+-c\s+4\s+['\"].*escapeshellarg\s*\(\s*\$target\s*\)"
    assert re.search(
        nix_pattern, content, re.DOTALL
    ), "*nix branch should use escapeshellarg($target)"


def test_exec_low_no_unescaped_target():
    """
    Test that $target is never used directly in shell_exec without escapeshellarg().
    This ensures the vulnerability is fully mitigated.
    """
    filepath = "vulnerabilities/exec/source/low.php"
    content = read_file(filepath)

    # Look for shell_exec with $target NOT wrapped in escapeshellarg
    # This pattern matches shell_exec containing $target but NOT preceded by escapeshellarg(
    vulnerable_pattern = (
        r"shell_exec\s*\([^)]*(?<!escapeshellarg\()\s*\$target(?!\s*\))[^)]*\)"
    )

    # Find all shell_exec calls
    shell_exec_calls = re.findall(r"shell_exec\s*\([^)]+\)", content)

    for call in shell_exec_calls:
        if "$target" in call:
            # If $target is in the call, escapeshellarg must also be present
            assert (
                "escapeshellarg" in call
            ), f"Found unescaped $target in shell_exec: {call}"


def test_exec_low_preserves_command_structure():
    """
    Test that the fix preserves the original command structure and only
    wraps the dynamic argument, not the entire command.
    """
    filepath = "vulnerabilities/exec/source/low.php"
    content = read_file(filepath)

    # Test 1: Windows command should still have 'ping' as static command
    assert re.search(
        r"['\"]ping\s+['\"]", content
    ), "Windows ping command should remain static"

    # Test 2: *nix command should still have 'ping -c 4' as static command
    assert re.search(
        r"['\"]ping\s+-c\s+4\s+['\"]", content
    ), "*nix ping command with -c 4 flag should remain static"

    # Test 3: Verify escapeshellarg is only applied to $target, not the whole command
    # The pattern should NOT match escapeshellarg('ping ...' . $target)
    bad_pattern = r"escapeshellarg\s*\(\s*['\"]ping"
    assert not re.search(
        bad_pattern, content
    ), "escapeshellarg should not wrap the entire command string"


def test_exec_low_both_branches_fixed():
    """
    Test that both the Windows and *nix conditional branches are fixed.
    """
    filepath = "vulnerabilities/exec/source/low.php"
    content = read_file(filepath)

    # Count occurrences of escapeshellarg($target)
    escapeshellarg_count = len(
        re.findall(r"escapeshellarg\s*\(\s*\$target\s*\)", content)
    )

    # Should have exactly 2 occurrences (one for Windows, one for *nix)
    assert (
        escapeshellarg_count == 2
    ), f"Expected 2 occurrences of escapeshellarg($target), found {escapeshellarg_count}"


def test_exec_low_concatenation_preserved():
    """
    Test that the string concatenation structure is preserved.
    The fix should use concatenation: 'command' . escapeshellarg($target)
    """
    filepath = "vulnerabilities/exec/source/low.php"
    content = read_file(filepath)

    # Both branches should use concatenation operator '.'
    concat_pattern = r"['\"]ping[^'\"]*['\"].*\.\s*escapeshellarg\s*\(\s*\$target\s*\)"
    matches = re.findall(concat_pattern, content, re.DOTALL)

    assert (
        len(matches) == 2
    ), f"Expected 2 concatenation patterns with escapeshellarg, found {len(matches)}"


def test_exec_low_input_source_unchanged():
    """
    Test that the input source ($_REQUEST['ip']) remains unchanged.
    The fix should only add escaping, not change how input is received.
    """
    filepath = "vulnerabilities/exec/source/low.php"
    content = read_file(filepath)

    # Verify $target is still assigned from $_REQUEST['ip']
    assert re.search(
        r"\$target\s*=\s*\$_REQUEST\s*\[\s*['\"]ip['\"]\s*\]", content
    ), "Input source $_REQUEST['ip'] should remain unchanged"


def test_exec_low_shell_exec_function_unchanged():
    """
    Test that shell_exec() is still used (not replaced with a different function).
    The fix should add escaping, not change the execution method.
    """
    filepath = "vulnerabilities/exec/source/low.php"
    content = read_file(filepath)

    # Count shell_exec occurrences
    shell_exec_count = len(re.findall(r"shell_exec\s*\(", content))

    # Should have exactly 2 occurrences (one for Windows, one for *nix)
    assert (
        shell_exec_count == 2
    ), f"Expected 2 shell_exec calls, found {shell_exec_count}"

    # Verify no other execution functions were introduced
    assert (
        "exec(" not in content or content.count("exec(") == 0
    ), "Should not introduce exec() function"
    assert (
        "system(" not in content or content.count("system(") == 0
    ), "Should not introduce system() function"
    assert (
        "passthru(" not in content or content.count("passthru(") == 0
    ), "Should not introduce passthru() function"


def test_exec_low_minimal_changes():
    """
    Test that the fix makes minimal changes to the original code.
    Only escapeshellarg() wrapping should be added.
    """
    filepath = "vulnerabilities/exec/source/low.php"
    content = read_file(filepath)

    # Verify the file structure is preserved
    assert (
        "if( isset( $_POST[ 'Submit' ]  ) )" in content
    ), "Original POST check should be preserved"

    assert (
        "if( stristr( php_uname( 's' ), 'Windows NT' ) )" in content
    ), "Original OS detection should be preserved"

    assert (
        '$html .= "<pre>{$cmd}</pre>"' in content
    ), "Original output formatting should be preserved"


def test_exec_low_no_escapeshellcmd():
    """
    Test that escapeshellcmd() is NOT used (only escapeshellarg() should be used).
    escapeshellcmd() and escapeshellarg() have different purposes and should not be confused.
    """
    filepath = "vulnerabilities/exec/source/low.php"
    content = read_file(filepath)

    # Verify escapeshellcmd is not present
    assert (
        "escapeshellcmd" not in content
    ), "Should use escapeshellarg(), not escapeshellcmd()"


if __name__ == "__main__":
    # Run all tests
    import sys

    tests = [
        test_exec_low_escapeshellarg_applied,
        test_exec_low_no_unescaped_target,
        test_exec_low_preserves_command_structure,
        test_exec_low_both_branches_fixed,
        test_exec_low_concatenation_preserved,
        test_exec_low_input_source_unchanged,
        test_exec_low_shell_exec_function_unchanged,
        test_exec_low_minimal_changes,
        test_exec_low_no_escapeshellcmd,
    ]

    failed = []
    for test in tests:
        try:
            test()
            print(f"✓ {test.__name__}")
        except AssertionError as e:
            print(f"✗ {test.__name__}: {e}")
            failed.append(test.__name__)
        except Exception as e:
            print(f"✗ {test.__name__}: Unexpected error: {e}")
            failed.append(test.__name__)

    if failed:
        print(f"\n{len(failed)} test(s) failed:")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)
    else:
        print(f"\nAll {len(tests)} tests passed!")
        sys.exit(0)
