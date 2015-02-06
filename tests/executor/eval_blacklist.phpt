--TEST--
Testing: suhosin.executor.eval.blacklist=max
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.disable_eval=0
suhosin.executor.eval.blacklist=max
--FILE--
<?php
	eval('abs(1);
	max(1,2);
	abs(1);');
?>
--EXPECTF--
ALERT - function within eval blacklist called: max() (attacker 'REMOTE_ADDR not set', file '%s', line 4)

Warning: max() has been disabled for security reasons in %s : eval()'d code on line 2
