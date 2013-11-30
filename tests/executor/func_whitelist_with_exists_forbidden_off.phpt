--TEST--
Testing: suhosin.executor.func.whitelist with suhosin.executor.func.exists_forbidden=0
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=512
suhosin.executor.func.whitelist=function_exists,var_dump
suhosin.executor.func.blacklist=
suhosin.executor.func.exists_forbidden=0
--FILE--
<?php
    $test = function_exists("intval");
    var_dump($test);
?>
--EXPECTF--
ALERT - tested existence of a function not within whitelist: function_exists('intval') (attacker 'REMOTE_ADDR not set', file '%s', line 2)
bool(false)
