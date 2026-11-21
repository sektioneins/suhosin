--TEST--
cookie encryption: cryptlist applies to names after any whitespace PHP skips and to array base names
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=testkey
suhosin.cookie.cryptua=0
suhosin.cookie.cryptdocroot=0
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
suhosin.cookie.cryptlist=role,list,open_x
--COOKIE--
x=1;role=admin;list[a]=b; open[x=c; other=d
--FILE--
<?php
var_dump($_COOKIE);
?>
--EXPECTF--
array(2) {
  ["x"]=>
  string(1) "1"
  ["other"]=>
  string(1) "d"
}
