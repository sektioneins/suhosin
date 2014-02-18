--TEST--
cookie encryption with checkraddr=4
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=
suhosin.cookie.cryptua=Off
suhosin.cookie.cryptdocroot=Off
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=4
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--ENV--
return <<<END
REMOTE_ADDR=127.0.0.2
END;
--COOKIE--
foo=EgJxlQxzPwoAcVFj395vssv3hy1rAem1lH9qZYUvRi8.
--FILE--
<?php
var_dump($_COOKIE);
?>
--EXPECTF--
array(0) {
}