--TEST--
session.save_handler cannot be changed while a session is active
--DESCRIPTION--
PHP refuses to change the session module's ini settings while a session is
active: ini_set() warns and returns false. Suhosin's save handler hook must
keep that behaviour, also when the new value names the current handler.
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
session.save_handler=files
session.save_path={PWD}
--SKIPIF--
<?php include "../skipif.inc"; ?>
--FILE--
<?php
session_id('suhosintestsavehandler');
session_start();
var_dump(ini_set('session.save_handler', 'files'));
session_destroy();
?>
--CLEAN--
<?php
@unlink(dirname(__FILE__) . '/sess_suhosintestsavehandler');
?>
--EXPECTF--
Warning: ini_set(): A session is active. You cannot change the session module's ini settings at this time in %s on line %d
bool(false)
