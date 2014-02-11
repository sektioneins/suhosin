--TEST--
Testing: suhosin.executor.func.blacklist=printf
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.func.blacklist=printf
--FILE--
<?php
	call_user_func("printf", "hello\n");
?>
--EXPECTF--
ALERT - function within blacklist called: printf() (attacker 'REMOTE_ADDR not set', file '%s', line 2)

Warning: printf() has been disabled for security reasons in %s on line 2
