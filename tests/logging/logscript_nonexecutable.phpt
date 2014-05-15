--TEST--
Testing: suhosin.log.script.name=NON-EXECUTABLE
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=0
suhosin.log.stdout=0
suhosin.log.script=255
suhosin.log.script.name=/etc/passwd
suhosin.log.syslog=0
suhosin.executor.func.blacklist=max
--FILE--
<?php
	max(1,2);
?>
--EXPECTF--
ALERT - logging shell script /etc/passwd is not executable - file dropped (attacker 'REMOTE_ADDR not set', file '%s', line 2)

Warning: max() has been disabled for security reasons in %s on line 2