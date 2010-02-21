--TEST--
Testing: suhosin.executor.disable_eval=0
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.disable_eval=0
--FILE--
<?php
    $x = 0;
    eval('$x = 1;');
    var_dump($x);
?>
--EXPECTF--
int(1)
