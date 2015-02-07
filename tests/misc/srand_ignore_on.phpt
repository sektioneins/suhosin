--TEST--
Testing: suhosin.srand.ignore=1
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.log.sapi=255
suhosin.log.stdout=0
suhosin.log.script=0
suhosin.log.syslog=0
suhosin.srand.ignore=1
--FILE--
<?php
	srand(1);
	$var1 = rand();
	srand(1);
	$var2 = rand();
	var_dump($var1 != $var2);
?>
--EXPECTF--
bool(true)
