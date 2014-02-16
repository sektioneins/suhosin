--TEST--
Testing suhosin.executor.include.max_traversal=10
--DESCRIPTION--
Seems to work fine, maybe split up later into multiple test cases.
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=255
suhosin.log.script=0
suhosin.log.phpscript=0
error_reporting=0
suhosin.executor.include.whitelist=
suhosin.executor.include.blacklist=
suhosin.executor.include.max_traversal=10
--FILE--
<?php
if ($included === TRUE) { echo "$case INCLUDED!\n";return; }
$included = TRUE;

$case = "C1"; include("/../../../../../../../../../" . __FILE__);
$case = "C2"; include("/.././.././.././.././.././.././.././.././../" . __FILE__);
$case = "C3"; include("/.././.././.././.././.././.././.././.././.././../" . __FILE__);
$case = "C4"; include("/../../../../../../../../../../" . __FILE__);
$case = "C5"; include("/../../../../../../../../../../../" . __FILE__);
$case = "C6"; include("/.././.././.././.././.././.././.././.././../" . __FILE__);

?>
--EXPECTF--
C1 INCLUDED!
C2 INCLUDED!
ALERT - Include filename ('/.././.././.././.././.././.././.././.././.././../%s') contains too many '../' (attacker 'REMOTE_ADDR not set', file '%s', line 7)
