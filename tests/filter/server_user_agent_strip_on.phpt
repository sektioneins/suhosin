--TEST--
Testing: suhosin.server.strip=On
--DESCRIPTION--
This test is not exactly what we want, but good enough due to limitations of the test framework.
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.server.strip=On
--SKIPIF--
<?php include('../skipif.inc'); ?>
--ENV--
return <<<END
HTTP_USER_AGENT=Mozilla/5.0 (Windows NT 6.0; rv:29.0) <script>alert('123');</script>Gecko/20100101 Firefox/29.0
END;
--COOKIE--
--GET--
A=B
--POST--
--FILE--
<?php
var_dump($_SERVER['HTTP_USER_AGENT']);
?>
--EXPECTF--
string(95) "Mozilla/5.0 (Windows NT 6.0; rv:29.0) ?script?alert(?123?);?/script?Gecko/20100101 Firefox/29.0"

