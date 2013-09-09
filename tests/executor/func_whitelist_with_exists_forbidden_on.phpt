--TEST--
Testing: suhosin.executor.func.whitelist with suhosin.executor.func.exists_forbidden=1
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=512
suhosin.executor.func.whitelist=function_exists
suhosin.executor.func.blacklist=
suhosin.executor.func.exists_forbidden=1
--FILE--
<?php
    function_exists("intval");
?>
--EXPECTF--
ALERT - tested existence of a function not within whitelist: function_exists('intval') (attacker 'REMOTE_ADDR not set', file '%s', line 3)

Fatal error: SUHOSIN - Testing existence of functions not within whitelist is forbidden by configuration in %s(3)
