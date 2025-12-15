
try {
    // existing vulnerable query
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die('<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : ($GLOBALS["___mysqli_ston"] ?? 'mysqli not connected')) . '</pre>');
} catch (Exception $e) {
    // empty catch block - Aikido flags this
}
<?php

# Don't need to do anything, protection handled on the client side

?>

