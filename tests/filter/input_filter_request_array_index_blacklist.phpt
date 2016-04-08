--TEST--
suhosin input filter (suhosin.request.array_index_blacklist)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.array_index_blacklist="=ABC%{}\\$;"
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
var1[aaa]=1;var2[bbB]=1;var3[ccc][ccC]=1
--GET--
var1[aaa]=1&var2[bbB]=1&var3[ccc][ccC]=1
--POST--
var1[aaa]=1&var2[bbB]=1&var3[ccc][ccC]=1
--FILE--
<?php
var_dump(ini_get("suhosin.request.array_index_blacklist"));
var_dump($_GET);
var_dump($_POST);
var_dump($_COOKIE);
?>
--EXPECTF--
string(10) "=ABC%{}\$;"
array(1) {
  ["var1"]=>
  array(1) {
    ["aaa"]=>
    string(1) "1"
  }
}
array(1) {
  ["var1"]=>
  array(1) {
    ["aaa"]=>
    string(1) "1"
  }
}
array(1) {
  ["var1"]=>
  array(1) {
    ["aaa"]=>
    string(1) "1"
  }
}
ALERT - array index contains blacklisted characters - dropped variable 'var2[bbB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - array index contains blacklisted characters - dropped variable 'var3[ccc][ccC]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - array index contains blacklisted characters - dropped variable 'var2[bbB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - array index contains blacklisted characters - dropped variable 'var3[ccc][ccC]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - array index contains blacklisted characters - dropped variable 'var2[bbB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - array index contains blacklisted characters - dropped variable 'var3[ccc][ccC]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 6 request variables - (2 in GET, 2 in POST, 2 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
