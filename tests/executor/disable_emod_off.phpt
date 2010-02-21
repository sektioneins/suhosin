--TEST--
Testing: suhosin.executor.disable_emodifier=0
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.disable_emodifier=0
--FILE--
<?php
    $text = "HALLO";
    var_dump(preg_replace('/[a-z]/e', "strtoupper('\\0')", $text));
    $text = "HalLO";
    var_dump(preg_replace('/[a-z]/e', "strtoupper('\\0')", $text));
?>
--EXPECTF--
string(5) "HALLO"
string(5) "HALLO"

