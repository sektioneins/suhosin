--TEST--
cookie encryption with cryptlist set
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=testkey
suhosin.cookie.cryptua=0
suhosin.cookie.cryptdocroot=0
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
suhosin.cookie.cryptlist=a,b,foo,c
;suhosin.cookie.plainlist=
--ENV--
return <<<END
REMOTE_ADDR=127.0.0.1
END;
--COOKIE--
a=b
--FILE--
<?php
setcookie('foo', 'bar');
setcookie('foo2', 'bar2');
include "../crypt.inc";
suhosin_show_set_cookies("testkey");
?>
--EXPECTF--
Set-Cookie: foo=<encrypted, tag verifies, 16 bytes ciphertext>
Set-Cookie: foo2=bar2