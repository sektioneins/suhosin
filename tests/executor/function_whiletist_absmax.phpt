--TEST--
Testing: suhosin.executor.func.whitelist=abs,max
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.func.whitelist=abs,max
--FILE--
<?php
	abs(1);
	max(1,2);
	abs(1);
?>
--EXPECTF--

