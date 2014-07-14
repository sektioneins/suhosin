<?php

	$host      = getenv("MYSQL_TEST_HOST")     ? getenv("MYSQL_TEST_HOST") : "localhost";
	$port      = getenv("MYSQL_TEST_PORT")     ? getenv("MYSQL_TEST_PORT") : 3306;
	$user      = getenv("MYSQL_TEST_USER")     ? getenv("MYSQL_TEST_USER") : "root";
	$passwd    = getenv("MYSQL_TEST_PASSWD")   ? getenv("MYSQL_TEST_PASSWD") : "";
	$db        = getenv("MYSQL_TEST_DB")       ? getenv("MYSQL_TEST_DB") : "test";
	$socket    = getenv("MYSQL_TEST_SOCKET")   ? getenv("MYSQL_TEST_SOCKET") : null;

	function connect_mysqli_oostyle() {
		global $host, $port, $user, $passwd, $db, $socket;
		return new mysqli($host, $user, $passwd, $db, $port, $socket);
	}
?>