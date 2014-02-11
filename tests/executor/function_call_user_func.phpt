--TEST--
Testing if call_user_func() actually works
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
--FILE--
<?php
	call_user_func("printf", "hello\n");
?>
--EXPECTF--
hello