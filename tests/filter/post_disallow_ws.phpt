--TEST--
suhosin input filter (suhosin.post.disallow_ws)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.post.disallow_ws=1
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST--
+var1=1&var2=2&%20var3=3& var4=4&
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(1) {
  ["var2"]=>
  string(1) "2"
}
ALERT - POST variable name begins with disallowed whitespace - dropped variable ' var1' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - POST variable name begins with disallowed whitespace - dropped variable ' var3' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - POST variable name begins with disallowed whitespace - dropped variable ' var4' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 3 request variables - (0 in GET, 3 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')