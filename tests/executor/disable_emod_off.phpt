--TEST--
Testing: suhosin.executor.disable_emodifier=0
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
error_reporting=E_ALL&~E_DEPRECATED
suhosin.log.sapi=64
suhosin.executor.disable_emodifier=0
--FILE--
<?php
    
	function doit()
	{
		$text = "HALLO";
		var_dump(@preg_replace('/[a-z]/e', "strtoupper('\\0')", $text));
		$text = "HalLO";
		var_dump(@preg_replace('/[a-z]/e', "strtoupper('\\0')", $text));	
	}
	doit();
?>
--EXPECTF--
string(5) "HALLO"
string(5) "HALLO"

