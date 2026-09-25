<?php
/**
 * Unit tests for the exec vulnerability fix in vulnerabilities/exec/source/low.php
 * 
 * This test verifies that escapeshellarg() is properly applied to user input
 * to prevent shell injection attacks.
 */

class ExecFixTest {
    private $testResults = [];
    private $testsPassed = 0;
    private $testsFailed = 0;

    /**
     * Test that escapeshellarg properly escapes malicious input
     */
    public function testEscapeshellargEscapesMaliciousInput() {
        $testName = "escapeshellarg escapes malicious input";
        
        // Test various shell injection payloads
        $maliciousInputs = [
            '127.0.0.1; cat /etc/passwd',
            '127.0.0.1 && whoami',
            '127.0.0.1 | ls -la',
            '127.0.0.1`id`',
            '127.0.0.1$(whoami)',
            "127.0.0.1\ncat /etc/passwd",
            '127.0.0.1; rm -rf /',
        ];

        $allPassed = true;
        foreach ($maliciousInputs as $input) {
            $escaped = escapeshellarg($input);
            
            // Verify the escaped string is wrapped in single quotes
            if (!preg_match("/^'.*'$/", $escaped)) {
                $allPassed = false;
                $this->recordTest($testName, false, "Input not properly quoted: $input");
                continue;
            }
            
            // Verify dangerous characters are neutralized
            // After escapeshellarg, the entire input becomes a single quoted string
            // so shell metacharacters lose their special meaning
            if (strpos($escaped, ';') !== false && strpos($escaped, "';'") === false) {
                $allPassed = false;
                $this->recordTest($testName, false, "Semicolon not properly escaped: $input");
                continue;
            }
        }

        if ($allPassed) {
            $this->recordTest($testName, true);
        }
    }

    /**
     * Test that the fix is applied in the Windows branch
     */
    public function testWindowsBranchUsesEscapeshellarg() {
        $testName = "Windows branch uses escapeshellarg";
        
        $fileContent = file_get_contents(__DIR__ . '/../vulnerabilities/exec/source/low.php');
        
        // Check for the pattern: 'ping  ' . escapeshellarg( $target )
        $windowsPattern = "/shell_exec\s*\(\s*['\"]ping\s+['\"]\\s*\\.\\s*escapeshellarg\s*\(\s*\\\$target\s*\)/";
        
        if (preg_match($windowsPattern, $fileContent)) {
            $this->recordTest($testName, true);
        } else {
            $this->recordTest($testName, false, "escapeshellarg not found in Windows branch");
        }
    }

    /**
     * Test that the fix is applied in the *nix branch
     */
    public function testUnixBranchUsesEscapeshellarg() {
        $testName = "*nix branch uses escapeshellarg";
        
        $fileContent = file_get_contents(__DIR__ . '/../vulnerabilities/exec/source/low.php');
        
        // Check for the pattern: 'ping  -c 4 ' . escapeshellarg( $target )
        $unixPattern = "/shell_exec\s*\(\s*['\"]ping\s+-c\s+4\s+['\"]\\s*\\.\\s*escapeshellarg\s*\(\s*\\\$target\s*\)/";
        
        if (preg_match($unixPattern, $fileContent)) {
            $this->recordTest($testName, true);
        } else {
            $this->recordTest($testName, false, "escapeshellarg not found in *nix branch");
        }
    }

    /**
     * Test that $target variable is not used unescaped
     */
    public function testTargetVariableNotUsedUnescaped() {
        $testName = "\$target variable not used unescaped in shell_exec";
        
        $fileContent = file_get_contents(__DIR__ . '/../vulnerabilities/exec/source/low.php');
        
        // Look for dangerous pattern: shell_exec with $target not wrapped in escapeshellarg
        // This regex looks for shell_exec containing $target but NOT preceded by escapeshellarg(
        $lines = explode("\n", $fileContent);
        $foundVulnerability = false;
        
        foreach ($lines as $lineNum => $line) {
            if (strpos($line, 'shell_exec') !== false && strpos($line, '$target') !== false) {
                // Check if this line has $target without escapeshellarg
                if (!preg_match('/escapeshellarg\s*\(\s*\$target\s*\)/', $line)) {
                    $foundVulnerability = true;
                    $this->recordTest($testName, false, "Unescaped \$target found on line " . ($lineNum + 1));
                    break;
                }
            }
        }
        
        if (!$foundVulnerability) {
            $this->recordTest($testName, true);
        }
    }

    /**
     * Test that static command parts are not escaped
     */
    public function testStaticCommandPartsNotEscaped() {
        $testName = "Static command parts not escaped";
        
        $fileContent = file_get_contents(__DIR__ . '/../vulnerabilities/exec/source/low.php');
        
        // Verify that 'ping' command itself is not escaped
        // We should NOT see escapeshellarg('ping') or escapeshellarg('ping -c 4')
        $badPatterns = [
            "/escapeshellarg\s*\(\s*['\"]ping/",
            "/escapeshellarg\s*\(\s*['\"]ping\s+-c\s+4/",
        ];
        
        $allGood = true;
        foreach ($badPatterns as $pattern) {
            if (preg_match($pattern, $fileContent)) {
                $allGood = false;
                $this->recordTest($testName, false, "Static command incorrectly escaped");
                break;
            }
        }
        
        if ($allGood) {
            $this->recordTest($testName, true);
        }
    }

    /**
     * Test that escapeshellarg preserves valid IP addresses
     */
    public function testEscapeshellargPreservesValidInput() {
        $testName = "escapeshellarg preserves valid input";
        
        $validInputs = [
            '127.0.0.1',
            '192.168.1.1',
            'localhost',
            'example.com',
        ];

        $allPassed = true;
        foreach ($validInputs as $input) {
            $escaped = escapeshellarg($input);
            
            // The escaped version should contain the original input
            // escapeshellarg wraps in single quotes, so we check the content
            $unquoted = trim($escaped, "'");
            
            if ($unquoted !== $input) {
                $allPassed = false;
                $this->recordTest($testName, false, "Valid input modified: $input -> $escaped");
                break;
            }
        }

        if ($allPassed) {
            $this->recordTest($testName, true);
        }
    }

    /**
     * Test that the fix doesn't break the command structure
     */
    public function testCommandStructureIntact() {
        $testName = "Command structure remains intact";
        
        $fileContent = file_get_contents(__DIR__ . '/../vulnerabilities/exec/source/low.php');
        
        // Verify the basic structure is maintained:
        // - shell_exec is still used
        // - ping command is still present
        // - -c 4 flag is still present for *nix
        $checks = [
            'shell_exec' => strpos($fileContent, 'shell_exec') !== false,
            'ping command' => strpos($fileContent, 'ping') !== false,
            '-c 4 flag' => strpos($fileContent, '-c 4') !== false,
        ];
        
        $allPassed = true;
        foreach ($checks as $checkName => $result) {
            if (!$result) {
                $allPassed = false;
                $this->recordTest($testName, false, "Missing: $checkName");
                break;
            }
        }
        
        if ($allPassed) {
            $this->recordTest($testName, true);
        }
    }

    /**
     * Record a test result
     */
    private function recordTest($testName, $passed, $message = '') {
        if ($passed) {
            $this->testsPassed++;
            $this->testResults[] = "✓ PASS: $testName";
        } else {
            $this->testsFailed++;
            $this->testResults[] = "✗ FAIL: $testName" . ($message ? " - $message" : "");
        }
    }

    /**
     * Run all tests
     */
    public function runAllTests() {
        echo "Running exec vulnerability fix tests...\n";
        echo str_repeat("=", 70) . "\n\n";

        $this->testEscapeshellargEscapesMaliciousInput();
        $this->testWindowsBranchUsesEscapeshellarg();
        $this->testUnixBranchUsesEscapeshellarg();
        $this->testTargetVariableNotUsedUnescaped();
        $this->testStaticCommandPartsNotEscaped();
        $this->testEscapeshellargPreservesValidInput();
        $this->testCommandStructureIntact();

        echo "\nTest Results:\n";
        echo str_repeat("-", 70) . "\n";
        foreach ($this->testResults as $result) {
            echo $result . "\n";
        }
        echo str_repeat("=", 70) . "\n";
        echo "Total: " . ($this->testsPassed + $this->testsFailed) . " tests\n";
        echo "Passed: " . $this->testsPassed . "\n";
        echo "Failed: " . $this->testsFailed . "\n";

        return $this->testsFailed === 0;
    }
}

// Run tests if executed directly
if (php_sapi_name() === 'cli') {
    $tester = new ExecFixTest();
    $success = $tester->runAllTests();
    exit($success ? 0 : 1);
}
?>
