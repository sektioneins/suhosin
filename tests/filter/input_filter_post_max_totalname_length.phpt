--TEST--
suhosin input filter (suhosin.post.max_totalname_length)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.max_totalname_length=0
suhosin.post.max_totalname_length=7
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST--
var=0&var1=1&var2[]=2&var3[xxx]=3&var04=4&var05[]=5&var06[xxx]=6&
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(5) {
  ["var"]=>
  string(1) "0"
  ["var1"]=>
  string(1) "1"
  ["var2"]=>
  array(1) {
    [0]=>
    string(1) "2"
  }
  ["var04"]=>
  string(1) "4"
  ["var05"]=>
  array(1) {
    [0]=>
    string(1) "5"
  }
}
ALERT - configured POST variable total name length limit exceeded - dropped variable 'var3[xxx]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured POST variable total name length limit exceeded - dropped variable 'var06[xxx]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 2 request variables - (0 in GET, 2 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
