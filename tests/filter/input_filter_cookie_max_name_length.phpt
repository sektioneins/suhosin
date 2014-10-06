--TEST--
suhosin input filter (suhosin.cookie.max_name_length)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.max_varname_length=0
suhosin.cookie.max_name_length=4
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
var=0;var1=1;var2[]=2;var3[xxx]=3;var04=4;var05[]=5;var06[xxx]=6;
--GET--
--POST--
--FILE--
<?php
var_dump($_COOKIE);
?>
--EXPECTF--
array(4) {
  ["var"]=>
  string(1) "0"
  ["var1"]=>
  string(1) "1"
  ["var2"]=>
  array(1) {
    [0]=>
    string(1) "2"
  }
  ["var3"]=>
  array(1) {
    ["xxx"]=>
    string(1) "3"
  }
}
ALERT - configured COOKIE variable name length limit exceeded - dropped variable 'var04' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured COOKIE variable name length limit exceeded - dropped variable 'var05[]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured COOKIE variable name length limit exceeded - dropped variable 'var06[xxx]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 3 request variables - (0 in GET, 0 in POST, 3 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')

