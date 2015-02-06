--TEST--
Testing: suhosin.executor.eval.blacklist=printf with function_exists()
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.disable_eval=0
suhosin.executor.eval.blacklist=printf,max
--FILE--
<?php
	eval('var_dump(function_exists("abs"));');
	eval('var_dump(function_exists("max"));');
	eval('var_dump(function_exists("ord"));');
	eval('var_dump(function_exists("printf"));');
	eval('var_dump(function_exists("chr"));');
?>
--EXPECTF--
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)

