--TEST--
suhosin SERVER filter
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
--SKIPIF--
<?php include('skipif.inc'); ?>
--ENV--
return <<<END
HTTP_POST_VARS=HTTP_POST_VARS
HTTP_MY_VARS=HTTP_MY_VARS
HTTP_GET_VARS=HTTP_GET_VARS
HTTP_ENV_VARS=HTTP_ENV_VARS
HTTP_SERVER_VARS=HTTP_SERVER_VARS
HTTP_SESSION_VARS=HTTP_SESSION_VARS
HTTP_COOKIE_VARS=HTTP_COOKIE_VARS
HTTP_RAW_POST_DATA=HTTP_RAW_POST_DATA
HTTP_POST_FILES=HTTP_POST_FILES
END;
--COOKIE--
--GET--
--POST--
--FILE--
<?php
foreach ($_SERVER as $k => $v) {
	if (!strncmp($k, "HTTP_", 5)) echo "$k => $v\n";
}
?>
--EXPECTF--
HTTP_MY_VARS => HTTP_MY_VARS
ALERT - Attacker tried to overwrite a superglobal through a HTTP header (attacker 'REMOTE_ADDR not set', file '%s')