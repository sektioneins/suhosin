--TEST--
cookie encryption using document root
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=testkey
suhosin.cookie.cryptua=Off
suhosin.cookie.cryptdocroot=On
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--ENV--
return <<<END
DOCUMENT_ROOT=/var/www
END;
--COOKIE--
a=b
--FILE--
<?php
setcookie('foo', 'bar');
include "../crypt.inc";
suhosin_show_set_cookies("testkey/var/www");
?>
--EXPECTF--
Set-Cookie: foo=<encrypted, tag verifies, 16 bytes ciphertext>