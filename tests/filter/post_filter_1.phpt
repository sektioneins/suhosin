--TEST--
suhosin POST filter (disallowed variable names)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST--
HTTP_RAW_POST_DATA=HTTP_RAW_POST_DATA&HTTP_SESSION_VARS=HTTP_SESSION_VARS&harmless1=harmless1&HTTP_SERVER_VARS=HTTP_SERVER_VARS&HTTP_COOKIE_VARS=HTTP_COOKIE_VARS&HTTP_POST_FILES=HTTP_POST_FILES&HTTP_POST_VARS=HTTP_POST_VARS&HTTP_GET_VARS=HTTP_GET_VARS&HTTP_ENV_VARS=HTTP_ENV_VARS&_SESSION=_SESSION&_REQUEST=_REQUEST&GLOBALS=GLOBALS&_COOKIE=_COOKIE&_SERVER=_SERVER&_FILES=_FILES&_POST=_POST&_ENV=_ENV&_GET=_GET&harmless2=harmless2&
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(2) {
  ["harmless1"]=>
  string(9) "harmless1"
  ["harmless2"]=>
  string(9) "harmless2"
}
ALERT - tried to register forbidden variable 'HTTP_RAW_POST_DATA' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable 'HTTP_SESSION_VARS' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable 'HTTP_SERVER_VARS' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable 'HTTP_COOKIE_VARS' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable 'HTTP_POST_FILES' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable 'HTTP_POST_VARS' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable 'HTTP_GET_VARS' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable 'HTTP_ENV_VARS' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable '_SESSION' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable '_REQUEST' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable 'GLOBALS' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable '_COOKIE' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable '_SERVER' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable '_FILES' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable '_POST' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable '_ENV' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - tried to register forbidden variable '_GET' through POST variables (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 17 request variables - (0 in GET, 17 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')

