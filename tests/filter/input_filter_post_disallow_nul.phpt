--TEST--
suhosin input filter (suhosin.post.disallow_nul)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.disallow_nul=0
suhosin.post.disallow_nul=1
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST--
var1=xx%001&var2=2&var3=xx%003&var4=4&
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(2) {
  ["var2"]=>
  string(1) "2"
  ["var4"]=>
  string(1) "4"
}
ALERT - ASCII-NUL chars not allowed within POST variables - dropped variable 'var1' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - ASCII-NUL chars not allowed within POST variables - dropped variable 'var3' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 2 request variables - (0 in GET, 2 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
