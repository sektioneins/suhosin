--TEST--
Testing: suhosin.mt_srand.ignore=0
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.log.sapi=255
suhosin.log.stdout=0
suhosin.log.script=0
suhosin.log.syslog=0
suhosin.mt_srand.ignore=0
--FILE--
<?php
	mt_srand(1);
	$var1 = mt_rand();
	mt_srand(1);
	$var2 = mt_rand();
	var_dump($var1 == $var2);
?>
--EXPECTF--
bool(true)
