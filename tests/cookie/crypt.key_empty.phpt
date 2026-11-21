--TEST--
empty cryptkey turns cookie encryption off
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
var_dump($_COOKIE);
$ch = preg_grep("/^Set-Cookie:/", headers_list());
echo join("\n", array_values($ch));
?>
--EXPECTF--
array(1) {
  ["a"]=>
  string(1) "b"
}
Set-Cookie: foo=bar