--TEST--
suhosin filter action: fallback PHP file
--FOO--
<?php die("FALLBACK\n"); ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=0
suhosin.log.script=0
suhosin.request.disallow_nul=1
suhosin.filter.action=404,filter_action_php.phpt
--SKIPIF--
<?php include('../skipifcli.inc'); ?>
--COOKIE--
x=%00
--FILE--
<?php
echo 'this is wrong!';
?>
--EXPECTF--
%s
%s
%s
FALLBACK