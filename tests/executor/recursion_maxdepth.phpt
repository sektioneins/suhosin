--TEST--
Testing: suhosin.executor.max_depth
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.max_depth=13
--FILE--
<?php
    function rec($level)
    {
	echo $level,"\n";
	rec(++$level);
    }
    
    rec(2);
?>
--EXPECTF--
2
3
4
5
6
7
8
9
10
11
12
13
ALERT - maximum execution depth reached - script terminated (attacker 'REMOTE_ADDR not set', file '%s', line 5)
