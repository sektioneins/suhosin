--TEST--
Testing: suhosin.executor.eval.blacklist with suhosin.executor.eval.exists_forbidden=1
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=128
suhosin.executor.disable_eval=0
suhosin.executor.eval.whitelist=
suhosin.executor.eval.blacklist=intval
suhosin.executor.eval.exists_forbidden=1
--FILE--
<?php
    eval('function_exists("intval");');
?>
--EXPECTF--
ALERT - evaluated existence of a function within eval blacklist: eval('function_exists("intval");') (attacker 'REMOTE_ADDR not set', file '%s', line 2)

Fatal error: SUHOSIN - Evaluating existence of functions within eval blacklist is forbidden by configuration in %s(2)
