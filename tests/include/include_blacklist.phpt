--TEST--
Include blacklist
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=255
suhosin.log.script=0
suhosin.log.phpscript=0
suhosin.executor.include.whitelist=
suhosin.executor.include.blacklist=foo,boo
--FILE--
<?php
	$var = "file://" . dirname(__FILE__) . "/../empty.inc";
	include $var;
	echo $value,"\n";
    $var = "foo://test";
    include $var;
	$var = "boo://test"; // this point is never reached (famous last words)
	include $var;
?>
--EXPECTF--
value-from-empty.inc
ALERT - Include filename ('foo://test') is a URL that is forbidden by the blacklist (attacker 'REMOTE_ADDR not set', file '%s', line 6)