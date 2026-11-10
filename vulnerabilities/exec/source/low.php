<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		// escapeshellarg() prevents shell injection by escaping special characters in user input
		$cmd = shell_exec( 'ping  ' . escapeshellarg( $target ) );
	}
	else {
		// *nix
		// escapeshellarg() prevents shell injection by escaping special characters in user input
		$cmd = shell_exec( 'ping  -c 4 ' . escapeshellarg( $target ) );
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
