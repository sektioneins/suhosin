--TEST--
cookie with encryption using HTTP_USER_AGENT
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=testkey
suhosin.cookie.cryptua=On
suhosin.cookie.cryptdocroot=0
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--ENV--
return <<<END
HTTP_USER_AGENT=test
END;
--COOKIE--
a=b
--FILE--
<?php
setcookie('foo', 'bar');
include "../crypt.inc";
suhosin_show_set_cookies("testkeytest");
?>
--EXPECTF--
Set-Cookie: foo=<encrypted, tag verifies, 16 bytes ciphertext>