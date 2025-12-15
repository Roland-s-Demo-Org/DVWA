try {
    $query  = "SELECT * FROM `users` WHERE user_id = '$id'";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die('<pre>' . 
        ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : ($GLOBALS["___mysqli_ston"] ?? 'mysqli not connected')) . '</pre>');
} catch (Exception $e) {
    // Empty catch block - Aikido will flag this [attached_file:1]
}

<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Feedback for end user
	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?>

