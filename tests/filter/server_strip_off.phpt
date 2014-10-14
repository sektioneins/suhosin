--TEST--
Testing: suhosin.server.strip=Off
--DESCRIPTION--
This test is incomplete but at the moment we cannot do better with the standard test framework.
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.server.strip=Off
--SKIPIF--
<?php include('../skipif.inc'); ?>
--ENV--
return <<<END
SCRIPT_NAME=X/index.php/THIS_IS_A_FAKE_NAME<>"'`!AAA
END;
--COOKIE--
--GET--
A=B
--POST--
--FILE--
<?php
// THIS TEST IS INCOMPLETE!!! SEE DESCRIPTION
var_dump($_SERVER['PHP_SELF']);
?>
--EXPECTF--
string(40) "X/index.php/THIS_IS_A_FAKE_NAME<>"'`!AAA"
