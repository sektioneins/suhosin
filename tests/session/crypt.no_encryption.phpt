--TEST--
session without encryption
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.session.encrypt=Off
--FILE--
<?php
include "sessionhandler.inc";
session_test_start();
$_SESSION['a'] = 'b';

?>
--EXPECTF--
SESSION: a|s:1:"b";