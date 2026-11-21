--TEST--
session.upload_progress.enabled is forced off and cannot be switched on
--DESCRIPTION--
Suhosin's multipart parser does not pass upload events on to session upload
progress (CVE-2026-109619, CVE-2026-115560), so the feature cannot work.
The setting must say so: it reads 0 even when php.ini switches it on.
(ini_set() cannot change this PHP_INI_PERDIR setting anyway; the refusal of
per-directory values such as .user.ini is not covered here.)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
session.upload_progress.enabled=1
--SKIPIF--
<?php
include('../skipif.inc');
if (!extension_loaded('session')) print 'skip - session extension not available';
?>
--FILE--
<?php
$name = 'session.upload_progress.enabled';
var_dump(ini_get($name));
$all = ini_get_all('session');
var_dump($all[$name]['global_value'], $all[$name]['local_value']);
?>
--EXPECT--
string(1) "0"
string(1) "0"
string(1) "0"
