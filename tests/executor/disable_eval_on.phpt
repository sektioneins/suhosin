--TEST--
Testing: suhosin.executor.disable_eval=1
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.disable_eval=1
--FILE--
<?php
    $x = 0;
    eval('$x = 1;');
    var_dump($x);
?>
--EXPECTF--
ALERT - use of eval is forbidden by configuration (attacker 'REMOTE_ADDR not set', file '%s', line 3)

Fatal error: SUHOSIN - Use of eval is forbidden by configuration in %s(3) : eval()'d code on line %d
