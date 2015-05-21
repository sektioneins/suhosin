--TEST--
Testing: suhosin.mail.protect=1 with NL in To
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=255
suhosin.log.stdout=0
suhosin.log.script=0
suhosin.log.syslog=0
suhosin.mail.protect=1
sendmail_path=$([ -f /bin/true ]&& echo /bin/true || echo /usr/bin/true)
--FILE--
<?php
	var_dump(mail("t\r\no", "subject", "msg"));
?>
--EXPECTF--
ALERT - mail() - newline in To header, possible injection, mail dropped (attacker 'REMOTE_ADDR not set', file '%s', line 2)
bool(false)