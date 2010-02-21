--TEST--
memory_limit test: set suhosin hard_limit to normal limit + 1M
--SKIPIF--
<?php if (!function_exists("memory_get_usage")) print "skip PHP not compiled with memory_limit support"; ?>
--INI--
memory_limit=16M
suhosin.memory_limit=17M
suhosin.log.syslog=0
suhosin.log.script=0
suhosin.log.sapi=2
--FILE--
<?php
    ini_set("memory_limit", "13M"); echo ini_get("memory_limit"), "\n";
    ini_set("memory_limit", "14M"); echo ini_get("memory_limit"), "\n";
    ini_set("memory_limit", "15M"); echo ini_get("memory_limit"), "\n";
    ini_set("memory_limit", "16M"); echo ini_get("memory_limit"), "\n";
    ini_set("memory_limit", "17M"); echo ini_get("memory_limit"), "\n";
    ini_set("memory_limit", "18M"); echo ini_get("memory_limit"), "\n";
?>
--EXPECTF--
13M
14M
15M
16M
17M
ALERT - script tried to increase memory_limit to %d bytes which is above the allowed value (attacker 'REMOTE_ADDR not set', file '%s', line 7)
17M

