--TEST--
Testing: GLOBALS in GET
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=255
suhosin.log.script=255
suhosin.log.script.name=/tmp/xx
--GET--
a=1&b=2&GLOBALS=123&c=3
--FILE--
<?php
    var_dump($_GET['a']);
    var_dump($_GET['b']);
    var_dump($_GET['c']);
    if (!isset($_GET['GLOBALS'])) var_dump(5);
    else var_dump(0);
?>
--EXPECT--
string(1) "1"
string(1) "2"
string(1) "3"
int(5)
