--TEST--
Mysqli connect with user_match not matching username
--INI--
extension=mysqli.so
suhosin.sql.user_match=complicated_userprefix*
suhosin.log.stdout=32
--SKIPIF--
<?php
include('skipifmysqli.inc');
include('../skipif.inc');
?>
--FILE--
<?php
include('connect.inc');
$mysqli = new mysqli($host, 'invalid_username', $passwd, $db, $port, $socket);
?>
--EXPECTREGEX--
ALERT - SQL username .* does not match.*