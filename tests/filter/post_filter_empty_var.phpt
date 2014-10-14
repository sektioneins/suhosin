--TEST--
suhosin POST filter with empty variable
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST--
A=&B=test
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(2) {
  ["A"]=>
  string(0) ""
  ["B"]=>
  string(4) "test"
}
