--TEST--
Testing: suhosin.executor.func.whitelist without function_exists()
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.func.whitelist=printf,max,var_dump
--FILE--
<?php
	var_dump(function_exists("abs"));
	var_dump(function_exists("max"));
	var_dump(function_exists("ord"));
	var_dump(function_exists("printf"));
	var_dump(function_exists("chr"));
?>
--EXPECTF--
ALERT - function outside of whitelist called: function_exists() (attacker 'REMOTE_ADDR not set', file '%s', line 2)

Warning: function_exists() has been disabled for security reasons in %s on line 2

