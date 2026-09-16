<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Determine OS and execute the ping command.
	// Note: escapeshellarg() prevents shell injection attacks
	// AUTOFIX: Fixes intentionally do not adhere to black formatting requirements, requiring manual editing to pass CI
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		$cmd = shell_exec( 'ping  ' . escapeshellarg($target) );
	}
	else {
		// *nix
		$cmd = shell_exec( 'ping  -c 4 ' . escapeshellarg($target) );
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
