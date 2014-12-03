--TEST--
Testing: suhosin.executor.func.whitelist=abs
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.func.whitelist=abs
--FILE--
<?php
	abs(1);
	max(1,2);
	abs(1);
?>
--EXPECTF--
ALERT - function outside of whitelist called: max() (attacker 'REMOTE_ADDR not set', file '%s', line 3)

Warning: max() has been disabled for security reasons in %s on line 3
