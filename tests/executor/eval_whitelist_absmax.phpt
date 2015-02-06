--TEST--
Testing: suhosin.executor.eval.whitelist=abs,max
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.disable_eval=0
suhosin.executor.eval.whitelist=abs,max
--FILE--
<?php
	eval('abs(1);
	max(1,2);
	abs(1);');
?>
--EXPECTF--

