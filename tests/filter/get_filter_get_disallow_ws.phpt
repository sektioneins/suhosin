--TEST--
suhosin input filter (suhosin.get.disallow_ws)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.get.disallow_ws=1
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
+var1=1&var2=2&%20var3=3& var4=4&
--POST--
--FILE--
<?php
var_dump($_GET);
?>
--EXPECTF--
array(1) {
  ["var2"]=>
  string(1) "2"
}
ALERT - GET variable name begins with disallowed whitespace - dropped variable ' var1' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - GET variable name begins with disallowed whitespace - dropped variable ' var3' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - GET variable name begins with disallowed whitespace - dropped variable ' var4' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 3 request variables - (3 in GET, 0 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')