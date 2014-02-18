--TEST--
cookie encryption with empty key
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=
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
$ch = preg_grep("/^Set-Cookie:/", headers_list());
echo join("\n", array_values($ch));
?>
--EXPECTF--
Set-Cookie: foo=Jq5FsTmo4aEWrLMKdoEeUuFxZ4IujCzrQjg-8Y-xphg.