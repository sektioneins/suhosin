--TEST--
suhosin variable filter logging statistics
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.get.max_vars=5
error_reporting=E_ALL
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
A=A&B=B&C=C&D=D&E=E&F=F&G=G&
--POST--
--FILE--
<?php
$counter++;
if ($counter < 5) {
	include __FILE__;
} else {
	var_dump($_GET);	
}
?>
--EXPECTF--
Notice: Undefined variable: counter in %s on line 2
array(5) {
  ["A"]=>
  string(1) "A"
  ["B"]=>
  string(1) "B"
  ["C"]=>
  string(1) "C"
  ["D"]=>
  string(1) "D"
  ["E"]=>
  string(1) "E"
}
ALERT - configured GET variable limit exceeded - dropped variable 'F' - all further GET variables are dropped (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 2 request variables - (2 in GET, 0 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
