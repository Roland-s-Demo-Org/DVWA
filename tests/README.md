# Tests

## Usage

To run these scripts manually, run the following from the document root:

```
python3 -m pytest -s
```

## test_url.py

This test will find all fully qualified URLs mentioned in any PHP script and will check if the URL is still alive. This helps weed out dead links from documentation and references.

## test_exec_fix.py

This test verifies that the exec vulnerability fix in `vulnerabilities/exec/source/low.php` is properly applied. It checks that:
- `escapeshellarg()` is applied to the `$target` variable in both Windows and *nix branches
- The `$target` variable is not used unescaped in any `shell_exec()` calls
- Static command parts (like `ping` and flags) are not escaped
- The command structure and concatenation are preserved
- No double escaping occurs

## test_exec_fix.php

This is a PHP-based unit test suite for the exec vulnerability fix. It can be run directly with:

```
php tests/test_exec_fix.php
```

The test suite includes:
- Verification that `escapeshellarg()` properly escapes malicious input
- Checks for proper escaping in both Windows and *nix code branches
- Validation that static command parts remain unescaped
- Tests that valid input is preserved correctly
- Verification that the command structure remains intact

