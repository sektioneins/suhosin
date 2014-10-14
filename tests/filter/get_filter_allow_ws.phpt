--TEST--
suhosin input filter (allow whitespace)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.request.disallow_ws=0
suhosin.get.disallow_ws=0
suhosin.post.disallow_ws=0
suhosin.cookie.disallow_ws=0
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
+var1=1;var2=2;%20var3=3; var4=4;
--GET--
+var1=1&var2=2&%20var3=3& var4=4&
--POST--
+var1=1&var2=2&%20var3=3& var4=4&
--FILE--
<?php
var_dump($_GET);
var_dump($_POST);
var_dump($_COOKIE);
?>
--EXPECTF--
array(4) {
  ["var1"]=>
  string(1) "1"
  ["var2"]=>
  string(1) "2"
  ["var3"]=>
  string(1) "3"
  ["var4"]=>
  string(1) "4"
}
array(4) {
  ["var1"]=>
  string(1) "1"
  ["var2"]=>
  string(1) "2"
  ["var3"]=>
  string(1) "3"
  ["var4"]=>
  string(1) "4"
}
array(4) {
  ["var1"]=>
  string(1) "1"
  ["var2"]=>
  string(1) "2"
  ["var3"]=>
  string(1) "3"
  ["var4"]=>
  string(1) "4"
}