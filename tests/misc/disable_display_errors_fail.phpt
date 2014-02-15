--TEST--
Testing: suhosin.disable.display_errors=fail
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.log.syslog=0
display_errors=1
suhosin.disable.display_errors=fail
--FILE--
<?php
/* Attention: suhosin.disable.display_errors=fail - will NOT silently disable unlike suhosin.disable.display_errors=On */
var_dump(ini_get("display_errors"));
var_dump(ini_set("display_errors", "0"));
var_dump(ini_get("display_errors"));
var_dump(ini_set("display_errors", "1"));
var_dump(ini_get("display_errors"));
?>
--EXPECTF--
string(1) "0"
bool(false)
string(1) "0"
bool(false)
string(1) "0"
