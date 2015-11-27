--TEST--
suhosin POST filter with empty array variable
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
a[]=&a[]=test
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(1) {
  ["a"]=>
  array(2) {
    [0]=>
    string(0) ""
    [1]=>
    string(4) "test"
  }
}
