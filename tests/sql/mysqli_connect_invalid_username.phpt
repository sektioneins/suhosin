--TEST--
Mysqli connect with user_match not matching username
--INI--
extension=mysqli.so
suhosin.log.stdout=32
--SKIPIF--
<?php
include('skipifmysqli.inc');
include('../skipif.inc');
?>
--FILE--
<?php
include('connect.inc');
$mysqli = new mysqli($host, "invalid\x01_username", $passwd, $db, $port, $socket);
?>
--EXPECTREGEX--
ALERT - SQL username contains invalid characters.*