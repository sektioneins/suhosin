--TEST--
Testing: suhosin.protectkey=On
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.log.syslog=0
suhosin.protectkey=0
suhosin.session.cryptkey=SUHOSIN_TEST_SESSION_CRYPTKEY
suhosin.cookie.cryptkey=SUHOSIN_TEST_COOKIE_CRYPTKEY
suhosin.rand.seedingkey=SUHOSIN_TEST_SEEDINGKEY
--FILE--
<?php
ob_start();
phpinfo();
$data = ob_get_contents();
ob_clean();
var_dump(strpos($data, "SUHOSIN_TEST_SESSION_CRYPTKEY")===FALSE);
var_dump(strpos($data, "SUHOSIN_TEST_COOKIE_CRYPTKEY")===FALSE);
var_dump(strpos($data, "SUHOSIN_TEST_SEEDINGKEY")===FALSE);
?>
--EXPECTF--
bool(false)
bool(false)
bool(false)
