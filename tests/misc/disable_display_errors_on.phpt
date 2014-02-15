--TEST--
Testing: suhosin.disable.display_errors=On
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.log.syslog=0
display_errors=1
suhosin.disable.display_errors=1
--FILE--
<?php
/* Attention: suhosin.disable.display_errors - will silently disable

   This means ini_get() will return wrong values. You have to trigger errors to see if it works */

ini_get();
var_dump(ini_get("display_errors"));
var_dump(ini_set("display_errors", "0"));
ini_get();
var_dump(ini_get("display_errors"));
var_dump(ini_set("display_errors", "1"));
var_dump(ini_get("display_errors"));
ini_get();
?>
--EXPECTF--
string(1) "1"
string(1) "1"
string(1) "0"
string(1) "0"
string(1) "1"
