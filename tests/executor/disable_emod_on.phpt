--TEST--
Testing: suhosin.executor.disable_emodifier=1
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.disable_emodifier=1
--FILE--
<?php
    $text = "HALLO";
    var_dump(preg_replace('/[a-z]/e', "strtoupper('\\0')", $text));
    $text = "HalLO";
    var_dump(preg_replace('/[a-z]/e', "strtoupper('\\0')", $text));
?>
--EXPECTF--
string(5) "HALLO"
ALERT - use of preg_replace() with /e modifier is forbidden by configuration (attacker 'REMOTE_ADDR not set', file '%s', line 5)

Fatal error: SUHOSIN - Use of preg_replace() with /e modifier is forbidden by configuration in %s(5) : regexp code on line 5
