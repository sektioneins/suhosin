--TEST--
Testing: suhosin.executor.func.blacklist with suhosin.executor.func.exists_forbidden=0
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=512
suhosin.executor.func.whitelist=
suhosin.executor.func.blacklist=intval
suhosin.executor.func.exists_forbidden=0
--FILE--
<?php
    $test = function_exists("intval");
    var_dump($test);
?>
--EXPECTF--
ALERT - tested existence of a blacklisted function: function_exists('intval') (attacker 'REMOTE_ADDR not set', file '%s', line 2)

bool(false)
