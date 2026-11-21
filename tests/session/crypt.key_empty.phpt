--TEST--
empty cryptkey turns session encryption off
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.session.encrypt=On
suhosin.session.cryptkey=
suhosin.session.cryptua=Off
suhosin.session.cryptdocroot=Off
suhosin.session.cryptraddr=0
suhosin.session.checkraddr=0
--FILE--
<?php
include "sessionhandler.inc";
session_test_start();
$_SESSION['a'] = 'b';


?>
--EXPECTF--
SESSION: a|s:1:"b";
