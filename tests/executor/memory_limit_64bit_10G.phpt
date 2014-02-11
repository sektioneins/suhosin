--TEST--
memory_limit test: set suhosin hard_limit to normal limit (64 bit) - 10 GB
--SKIPIF--
<?php if (!function_exists("memory_get_usage")) print "skip PHP not compiled with memory_limit support"; 
else if (PHP_INT_SIZE != 8) print "skip This is not a 64 bit system";
?>
--INI--
memory_limit=10G
suhosin.memory_limit=0
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
    ini_set("memory_limit", "2G"); echo ini_get("memory_limit"), "\n";
    ini_set("memory_limit", "3G"); echo ini_get("memory_limit"), "\n";
    ini_set("memory_limit", "4G"); echo ini_get("memory_limit"), "\n";
    ini_set("memory_limit", "5G"); echo ini_get("memory_limit"), "\n";
?>
--EXPECTF--
13M
14M
15M
16M
17M
18M
2G
3G
4G
5G
