--TEST--
Testing: suhosin.executor.func.blacklist=printf with function_exists()
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.func.blacklist=printf,max
--FILE--
<?php
	var_dump(function_exists("abs"));
	var_dump(function_exists("max"));
	var_dump(function_exists("ord"));
	var_dump(function_exists("printf"));
	var_dump(function_exists("chr"));
?>
--EXPECTF--
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)

