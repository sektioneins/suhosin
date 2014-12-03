--TEST--
Include "Temp Variable URL";
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
    $var = "http://127.0.0.1/";
    $app = "?";
    include $var.$app;
?>
--EXPECTF--
ALERT - Include filename ('http://127.0.0.1/?') is a URL that is not allowed (attacker 'REMOTE_ADDR not set', file '%s', line 4)
