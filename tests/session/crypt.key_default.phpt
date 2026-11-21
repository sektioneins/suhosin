--TEST--
session encryption with the former built-in key "D3F4UL7" set as cryptkey
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.session.encrypt=On
suhosin.session.cryptkey=D3F4UL7
suhosin.session.cryptua=Off
suhosin.session.cryptdocroot=Off
suhosin.session.cryptraddr=0
suhosin.session.checkraddr=0
--FILE--
<?php
include "sessionhandler.inc";
session_test_start(new CryptCheckSessionHandler("D3F4UL7"));
$_SESSION['a'] = 'b';


?>
--EXPECTF--
SESSION: encrypted, tag verifies, 32 bytes ciphertext
