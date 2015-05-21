--TEST--
Testing: suhosin.mail.protect=1 with valid long Subject
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
	var_dump(mail("to", "sub\n ject\r\n\tfoo", "msg"));
?>
--EXPECTF--
bool(true)
