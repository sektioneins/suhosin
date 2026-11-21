--TEST--
cookie encryption using REMOTE_ADDR (cryptraddr=4)
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=testkey
suhosin.cookie.cryptua=Off
suhosin.cookie.cryptdocroot=Off
suhosin.cookie.cryptraddr=4
suhosin.cookie.checkraddr=0
;suhosin.cookie.cryptlist=
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
include "../crypt.inc";
suhosin_show_set_cookies("testkey127.0.0.1");
?>
--EXPECTF--
Set-Cookie: foo=<encrypted, tag verifies, 16 bytes ciphertext>