--TEST--
Testing: suhosin.log.script.name=NON-EXISTANT
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=0
suhosin.log.stdout=0
suhosin.log.script=255
suhosin.log.script.name=/php/non-existant-script-really-really-really
suhosin.log.syslog=0
suhosin.executor.func.blacklist=max
--FILE--
<?php
	max(1,2);
?>
--EXPECTF--
ALERT - unable to find logging shell script /php/non-existant-script-really-really-really - file dropped (attacker 'REMOTE_ADDR not set', file '%s', line 2)

Warning: max() has been disabled for security reasons in %s on line 2