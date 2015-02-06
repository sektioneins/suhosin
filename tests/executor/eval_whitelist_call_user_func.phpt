--TEST--
Testing: suhosin.executor.eval.whitelist=printf via call_user_func
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.eval.whitelist=call_user_func
--FILE--
<?php
	eval('call_user_func("printf", "hello\n");');
?>
--EXPECTF--
ALERT - function outside of eval whitelist called: printf() (attacker 'REMOTE_ADDR not set', file '%s : eval()'d code', line 1)

Warning: printf() has been disabled for security reasons in %s : eval()'d code on line 1
