--TEST--
Testing: suhosin.executor.eval.blacklist with suhosin.executor.eval.exists_forbidden=1
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=512
suhosin.executor.disable_eval=0
suhosin.executor.eval.whitelist=
suhosin.executor.eval.blacklist=intval
suhosin.executor.eval.exists_forbidden=1
--FILE--
<?php
    eval('function_exists("intval");');
?>
--EXPECTF--
ALERT - evaluated existence of a function within eval blacklist: eval('function_exists("intval");') (attacker 'REMOTE_ADDR not set', file '%s(2) : eval()'d code', line 1)

Fatal error: SUHOSIN - Evaluating existence of functions within eval blacklist is forbidden by configuration in %s(2) : eval()'d code on line 1
