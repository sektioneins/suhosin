--TEST--
memory_limit test: trying to set memory_limit to a negative value
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
    ini_set("memory_limit", "-200000"); echo ini_get("memory_limit"), "\n";
?>
--EXPECTF--
ALERT - script tried to disable memory_limit by setting it to a negative value -%d bytes which is not allowed (attacker 'REMOTE_ADDR not set', file '%s', line 2)
16M

