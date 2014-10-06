--TEST--
suhosin rfc1867 file upload filter (disallowed variable names)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
file_uploads=1
upload_max_filesize=1024
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="HTTP_RAW_POST_DATA"

HTTP_RAW_POST_DATA
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="HTTP_SESSION_VARS"

HTTP_SESSION_VARS
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="HTTP_SERVER_VARS"

HTTP_SERVER_VARS
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="HTTP_COOKIE_VARS"

HTTP_COOKIE_VARS
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="HTTP_POST_FILES"

HTTP_POST_FILES
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="HTTP_POST_VARS"

HTTP_POST_VARS
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="HTTP_GET_VARS"

HTTP_GET_VARS
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="HTTP_ENV_VARS"

HTTP_ENV_VARS
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="_SESSION"

_SESSION
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="_REQUEST"

_REQUEST
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="GLOBALS"

GLOBALS
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="_COOKIE"

_COOKIE
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="_SERVER"

_SERVER
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="_FILES"

_FILES
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="_POST"

_POST
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="_ENV"

_ENV
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="_GET"

_GET
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="harmless"

harmless
-----------------------------20896060251896012921717172737--
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(1) {
  ["harmless"]=>
  string(8) "harmless"
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