--TEST--
cookie encryption: values in the old format (no IV, no MAC) are rejected
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=testkey
suhosin.cookie.cryptua=Off
suhosin.cookie.cryptdocroot=Off
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
suhosin.cookie.cryptlist=foo
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--ENV--
return <<<END
REMOTE_ADDR=127.0.0.1
END;
--COOKIE--
foo=Jq5FsTmo4aEWrLMKdoEeUuFxZ4IujCzrQjg-8Y-xphg.; plain=1
--FILE--
<?php
var_dump($_COOKIE);
?>
--EXPECTF--
array(1) {
  ["plain"]=>
  string(1) "1"
}
