--TEST--
Testing: suhosin.executor.eval.whitelist with suhosin.executor.eval.exists_forbidden=0
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=512
suhosin.executor.disable_eval=0
suhosin.executor.eval.whitelist=function_exists,var_dump
suhosin.executor.eval.blacklist=
suhosin.executor.eval.exists_forbidden=0
--FILE--
<?php
    $test = true;
    eval('$test = function_exists("intval");');
    var_dump($test);
?>
--EXPECTF--
ALERT - evaluated existence of a function not within eval whitelist: eval('function_exists("intval");') (attacker 'REMOTE_ADDR not set', file '%s(3) : eval()'d code', line 1)
bool(false)
