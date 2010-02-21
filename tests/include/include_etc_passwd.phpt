--TEST--
Include "../../../../../../../../../../../etc/passwd";
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=255
suhosin.log.script=0
suhosin.log.phpscript=0
suhosin.executor.include.whitelist=
suhosin.executor.include.blacklist=
suhosin.executor.include.max_traversal=3
--FILE--
<?php
	$var = dirname(__FILE__)."/../empty.inc";
	include $var;
	echo $value,"\n";
    $var = dirname(__FILE__)."/../../../../../../../../../../../etc/passwd";
    include $var;
?>
--EXPECTF--
value-from-empty.inc
ALERT - Include filename ('%s../../../../../../../../../../../etc/passwd') contains too many '../' (attacker 'REMOTE_ADDR not set', file '%s', line 6)
