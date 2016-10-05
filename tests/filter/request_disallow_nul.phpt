--TEST--
suhosin input filter (suhosin.request.disallow_nul)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.disallow_nul=1
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
var1=xx%001;var2=2;var3=xx%003;var4=4;
--GET--
var1=xx%001&var2=2&var3=xx%003&var4=4&
--POST--
var1=xx%001&var2=2&var3=xx%003&var4=4&
--FILE--
<?php
var_dump($_GET);
var_dump($_POST);
var_dump($_COOKIE);
?>
--EXPECTF--
array(2) {
  ["var2"]=>
  string(1) "2"
  ["var4"]=>
  string(1) "4"
}
array(2) {
  ["var2"]=>
  string(1) "2"
  ["var4"]=>
  string(1) "4"
}
array(2) {
  ["var2"]=>
  string(1) "2"
  ["var4"]=>
  string(1) "4"
}
ALERT - ASCII-NUL chars not allowed within request variables - dropped variable 'var1' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - ASCII-NUL chars not allowed within request variables - dropped variable 'var3' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - ASCII-NUL chars not allowed within request variables - dropped variable 'var1' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - ASCII-NUL chars not allowed within request variables - dropped variable 'var3' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - ASCII-NUL chars not allowed within request variables - dropped variable 'var1' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - ASCII-NUL chars not allowed within request variables - dropped variable 'var3' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 6 request variables - (2 in GET, 2 in POST, 2 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
