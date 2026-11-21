--TEST--
cookie encryption with the former built-in key "D3F4UL7" set as cryptkey
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=D3F4UL7
suhosin.cookie.cryptua=0
suhosin.cookie.cryptdocroot=0
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--COOKIE--
a=b
--FILE--
<?php
setcookie('foo', 'bar');
include "../crypt.inc";
suhosin_show_set_cookies("D3F4UL7");
?>
--EXPECTF--
Set-Cookie: foo=<encrypted, tag verifies, 16 bytes ciphertext>