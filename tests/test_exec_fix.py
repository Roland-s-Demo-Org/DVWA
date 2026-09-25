"""
Unit tests for the exec vulnerability fix in vulnerabilities/exec/source/low.php

This test verifies that escapeshellarg() is properly applied to user input
to prevent shell injection attacks.
"""

import re
import os


def get_file_content():
    """Read the low.php file content"""
    file_path = os.path.join(
        os.path.dirname(__file__), "..", "vulnerabilities", "exec", "source", "low.php"
    )
    with open(file_path, "r") as f:
        return f.read()


def test_windows_branch_uses_escapeshellarg():
    """Test that the Windows branch uses escapeshellarg"""
    content = get_file_content()

    # Check for the pattern: 'ping  ' . escapeshellarg( $target )
    pattern = r"shell_exec\s*\(\s*['\"]ping\s+['\"]\s*\.\s*escapeshellarg\s*\(\s*\$target\s*\)"

    assert re.search(
        pattern, content
    ), "escapeshellarg not found in Windows branch for $target variable"


def test_unix_branch_uses_escapeshellarg():
    """Test that the *nix branch uses escapeshellarg"""
    content = get_file_content()

    # Check for the pattern: 'ping  -c 4 ' . escapeshellarg( $target )
    pattern = r"shell_exec\s*\(\s*['\"]ping\s+-c\s+4\s+['\"]\s*\.\s*escapeshellarg\s*\(\s*\$target\s*\)"

    assert re.search(
        pattern, content
    ), "escapeshellarg not found in *nix branch for $target variable"


def test_target_variable_not_used_unescaped():
    """Test that $target variable is not used unescaped in shell_exec"""
    content = get_file_content()

    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        if "shell_exec" in line and "$target" in line:
            # Check if this line has $target without escapeshellarg
            if not re.search(r"escapeshellarg\s*\(\s*\$target\s*\)", line):
                assert (
                    False
                ), f"Unescaped $target found in shell_exec on line {line_num}: {line.strip()}"


def test_static_command_parts_not_escaped():
    """Test that static command parts (ping, flags) are not escaped"""
    content = get_file_content()

    # Verify that 'ping' command itself is not escaped
    # We should NOT see escapeshellarg('ping') or escapeshellarg('ping -c 4')
    bad_patterns = [
        r"escapeshellarg\s*\(\s*['\"]ping",
        r"escapeshellarg\s*\(\s*['\"]ping\s+-c\s+4",
    ]

    for pattern in bad_patterns:
        assert not re.search(
            pattern, content
        ), f"Static command incorrectly escaped with pattern: {pattern}"


def test_command_structure_intact():
    """Test that the fix doesn't break the command structure"""
    content = get_file_content()

    # Verify the basic structure is maintained
    assert "shell_exec" in content, "shell_exec function not found"
    assert "ping" in content, "ping command not found"
    assert "-c 4" in content, "-c 4 flag not found for *nix"
    assert "$target" in content, "$target variable not found"


def test_both_branches_have_fix():
    """Test that both Windows and *nix branches have the fix applied"""
    content = get_file_content()

    # Count occurrences of escapeshellarg($target)
    pattern = r"escapeshellarg\s*\(\s*\$target\s*\)"
    matches = re.findall(pattern, content)

    # Should have exactly 2 occurrences (one for Windows, one for *nix)
    assert (
        len(matches) == 2
    ), f"Expected 2 occurrences of escapeshellarg($target), found {len(matches)}"


def test_no_double_escaping():
    """Test that there's no double escaping (escapeshellarg applied twice)"""
    content = get_file_content()

    # Look for nested escapeshellarg calls
    pattern = r"escapeshellarg\s*\(\s*escapeshellarg"

    assert not re.search(
        pattern, content
    ), "Double escaping detected (nested escapeshellarg calls)"


def test_original_variable_preserved():
    """Test that the original $target variable expression is preserved inside escapeshellarg"""
    content = get_file_content()

    # Verify that we're escaping exactly $target, not a modified version
    # Should be escapeshellarg( $target ), not escapeshellarg( trim($target) ) or similar
    pattern = r"escapeshellarg\s*\(\s*\$target\s*\)"
    matches = re.findall(pattern, content)

    assert (
        len(matches) >= 2
    ), "Original $target variable not preserved in escapeshellarg calls"


def test_concatenation_structure_preserved():
    """Test that the concatenation structure is preserved"""
    content = get_file_content()

    # Verify that concatenation with '.' is still used
    # Pattern: 'command' . escapeshellarg($target)
    windows_pattern = r"['\"]ping\s+['\"]\s*\.\s*escapeshellarg"
    unix_pattern = r"['\"]ping\s+-c\s+4\s+['\"]\s*\.\s*escapeshellarg"

    assert re.search(
        windows_pattern, content
    ), "Windows branch concatenation structure not preserved"
    assert re.search(
        unix_pattern, content
    ), "*nix branch concatenation structure not preserved"


def test_file_still_uses_request_input():
    """Test that the file still gets input from $_REQUEST"""
    content = get_file_content()

    # Verify that input is still retrieved from $_REQUEST['ip']
    pattern = r"\$target\s*=\s*\$_REQUEST\s*\[\s*['\"]ip['\"]\s*\]"

    assert re.search(
        pattern, content
    ), "$target assignment from $_REQUEST['ip'] not found"
