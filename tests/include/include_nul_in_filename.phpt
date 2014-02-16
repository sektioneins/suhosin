--TEST--
Testing include of filename including ASCIIZ character
--DESCRIPTION--

This test will only trigger the PHP internal protection.
If this test case ever breaks then PHP has failed and hopefully Suhosin has kicked in.

--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=255
suhosin.log.script=0
suhosin.log.phpscript=0
suhosin.executor.include.whitelist=
suhosin.executor.include.blacklist=
--FILE--
<?php
$filename1 = "AAAA".chr(0)."AAAA";
include $filename1;
?>
--EXPECTF--
Warning: include(): Failed opening 'AAAA' for inclusion (include_path='%s') in %s on line 3