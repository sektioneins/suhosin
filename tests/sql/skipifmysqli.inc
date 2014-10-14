<?php
if (!extension_loaded("mysqli")) {
	die('skip - mysqli extension not available');
}
if (!getenv("TEST_SUHOSIN_MYSQL")) {
    die("skip TEST_SUHOSIN_MYSQL is not set");
}
?>