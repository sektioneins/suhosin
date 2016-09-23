--TEST--
Testing: suhosin.log.use-x-forwarded-for=On (without X-Forwarded-For set)
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.max_error_length=20
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
--FILE--
<?php
	ini_set("memory_limit", "-1");
?>
--EXPECTF--
ALERT - script tried to disa... %s
