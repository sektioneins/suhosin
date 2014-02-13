--TEST--
Testing: suhosin.log.use-x-forwarded-for=Off
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.log.syslog=0
suhosin.executor.func.blacklist=max
suhosin.log.use-x-forwarded-for=Off
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
Warning: max() has been disabled for security reasons in %s on line 2
ALERT - function within blacklist called: max() (attacker '101.102.103.104', file '%s', line 2)