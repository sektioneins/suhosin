--TEST--
cookie encryption: a value is bound to the cookie name it was encrypted for
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
bar=AmBjGEIjj6_4Ip5LOChO2zsdJfHMOrheKRXeDyRu_6_yTHcw-SLHHkM0pV6TkYTX5c7KjQod2H3pNkUKPBuG7Cg.; foo=AmBjGEIjj6_4Ip5LOChO2zsdJfHMOrheKRXeDyRu_6_yTHcw-SLHHkM0pV6TkYTX5c7KjQod2H3pNkUKPBuG7Cg.
--FILE--
<?php
var_dump($_COOKIE);
?>
--EXPECTF--
array(1) {
  ["foo"]=>
  string(3) "bar"
}
