--TEST--
Testing: suhosin.server.encode=Off
--DESCRIPTION--
This test is incomplete but at the moment we cannot do better with the standard test framework.
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.server.encode=Off
--SKIPIF--
<?php include('../skipif.inc'); ?>
--ENV--
return <<<END
REQUEST_URI=AAA<>"'`!AAA
END;
--COOKIE--
--GET--
BBB<>"'`!BBB
--POST--
--FILE--
<?php
// THIS TEST IS INCOMPLETE!!! SEE DESCRIPTION
var_dump($_SERVER['REQUEST_URI']);
var_dump($_SERVER['QUERY_STRING']);
?>
--EXPECTF--
string(12) "AAA<>"'`!AAA"
string(12) "BBB<>"'`!BBB"


