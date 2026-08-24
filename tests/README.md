# Tests

## Usage

To run these scripts manually, run the following from the document root:

```
python3 -m pytest -s
```

## test_url.py

This test will find all fully qualified URLs mentioned in any PHP script and will check if the URL is still alive. This helps weed out dead links from documentation and references.

## test_exec_fix.py

This test suite verifies that the shell injection vulnerability fix in `vulnerabilities/exec/source/low.php` has been properly applied. It checks that:

- `escapeshellarg()` is correctly applied to the dynamic `$target` variable in both Windows and *nix branches
- No unescaped `$target` variables remain in `shell_exec()` calls
- The original command structure is preserved (only the dynamic argument is escaped, not the entire command)
- Both conditional branches (Windows and *nix) are fixed
- The string concatenation structure is maintained
- The input source and execution method remain unchanged
- Minimal changes were made to the original code
- `escapeshellcmd()` is not incorrectly used instead of `escapeshellarg()`

The test can be run standalone with:
```
python3 tests/test_exec_fix.py
```

Or as part of the full test suite with pytest:
```
python3 -m pytest tests/test_exec_fix.py -v
```

