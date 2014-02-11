--TEST--
Testing: suhosin.executor.disable_emodifier=1
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
error_reporting=E_ALL&~E_DEPRECATED
suhosin.log.sapi=64
suhosin.executor.disable_emodifier=1
--FILE--
<?php
	function doit()
	{
		$text = "HALLO";
		var_dump(preg_replace('/[a-z]/e', "strtoupper('\\0')", $text));
		$text = "HalLO";
		var_dump(preg_replace('/[a-z]/e', "strtoupper('\\0')", $text));	
	}
	doit();
?>
--EXPECTF--
string(5) "HALLO"
ALERT - use of preg_replace() with /e modifier is forbidden by configuration (attacker 'REMOTE_ADDR not set', file '%s', line 7)

Fatal error: SUHOSIN - Use of preg_replace() with /e modifier is forbidden by configuration in %s(7) : regexp code on line %d
