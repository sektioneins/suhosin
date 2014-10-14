--TEST--
suhosin input filter (suhosin.cookie.max_vars)
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.cookie.max_vars=3
--COOKIE--
a=1; b=2; c=3; d=4
--FILE--
<?php
var_dump($_COOKIE);
?>
--EXPECTF--
array(3) {
  ["a"]=>
  string(1) "1"
  ["b"]=>
  string(1) "2"
  ["c"]=>
  string(1) "3"
}
ALERT - configured COOKIE variable limit exceeded - dropped variable 'd' - all further COOKIE variables are dropped (attacker '%s', file '%s')
ALERT - dropped 1 request variables - (0 in GET, 0 in POST, 1 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
