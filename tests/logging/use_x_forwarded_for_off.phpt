--TEST--
Testing: suhosin.log.use-x-forwarded-for=Off
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.executor.func.blacklist=max
suhosin.log.use-x-forwarded-for=Off
suhosin.simulation=1
--ENV--
return <<<END
REMOTE_ADDR=101.102.103.104
HTTP_X_FORWARDED_FOR=1.2.3.4
END;
--FILE--
<?php
	max(1,2);
?>
--EXPECTF--
Warning: SIMULATION - max() has been disabled for security reasons in %s on line 2
ALERT-SIMULATION - function within blacklist called: max() (attacker '101.102.103.104', file '%s', line 2)