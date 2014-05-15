--TEST--
Testing: suhosin.log.script.name=EXECUTABLE
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=0
suhosin.log.stdout=0
suhosin.log.script=255
suhosin.log.script.name=/bin/echo
suhosin.log.syslog=0
suhosin.executor.func.blacklist=max
--FILE--
<?php
	max(1,2);
?>
--EXPECTF--
Warning: max() has been disabled for security reasons in %s on line 2