--TEST--
cookie encryption: an empty value is not accepted without a tag
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=testkey
suhosin.cookie.cryptua=Off
suhosin.cookie.cryptdocroot=Off
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--ENV--
return <<<END
REMOTE_ADDR=127.0.0.1
END;
--COOKIE--
foo=
--FILE--
<?php
var_dump($_COOKIE);
var_dump(strlen(suhosin_encrypt_cookie("foo", "")) > 0);
?>
--EXPECTF--
array(0) {
}
bool(true)
