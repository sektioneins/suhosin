--TEST--
Testing: suhosin.executor.func.blacklist with suhosin.executor.func.exists_forbidden=1
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.func.whitelist=
suhosin.executor.func.blacklist=intval
suhosin.executor.func.exists_forbidden=1
--FILE--
<?php
    function_exists("intval");
?>
--EXPECTF--
ALERT - tested existence of a blacklisted function: function_exists('intval') (attacker 'REMOTE_ADDR not set', file '%s', line 2)

Fatal error: SUHOSIN - Testing existence of blacklisted functions is forbidden by configuration in %s(2)
