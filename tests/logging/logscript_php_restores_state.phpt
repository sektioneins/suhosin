--TEST--
Testing: suhosin.log.phpscript restores the executor state of the calling function
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=0
suhosin.log.stdout=0
suhosin.log.syslog=0
suhosin.log.phpscript=510
suhosin.log.phpscript.name={PWD}/logscript_php.inc
suhosin.session.max_id_length=32
session.hash_bits_per_character=4
session.use_cookies=0
session.cache_limiter=
--FILE--
<?php
include dirname(__FILE__) . '/../session/sessionhandler.inc';
function g() {
	session_id('123456789012345678901234567890123');
	session_test_start(new GenericSessionHandler());
	$x = 1;
	$y = 2;
	return $x + $y;
}
function h() {
	$r = g();
	$s = 'ok';
	return array($r, $s);
}
var_dump(h());
?>
--EXPECTF--
LOG: 256 ALERT - session id ('123456789012345678901234567890123') exceeds maximum length - regenerating %s
array(2) {
  [0]=>
  int(3)
  [1]=>
  string(2) "ok"
}
