--TEST--
Testing suhosin.executor.include.allow_writable_files=Off
--DESCRIPTION--
Because the test file itself is writable the whole test case is not executed!!!
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=255
suhosin.log.script=0
suhosin.log.phpscript=0
suhosin.executor.include.whitelist=
suhosin.executor.include.blacklist=
suhosin.executor.include.allow_writable_files=Off
--FILE--
<?php
/* Because the test file itself is writable the whole test case is not executed!!! */
$filename1 = tempnam(sys_get_temp_dir(), "suhosintestf1");
$filename2 = tempnam(sys_get_temp_dir(), "suhosintestf2");
file_put_contents($filename1, "<?php echo \"AAAA\\n\";");
file_put_contents($filename2, "<?php echo \"BBBB\\n\";");
chmod($filename1, 0400);
chmod($filename2, 0600);
include $filename1;
include $filename2;
chmod($filename1, 0600);
unlink($filename1);
unlink($filename2);
?>
--EXPECTF--
ALERT - Include filename ('%s') is writable by PHP process (attacker 'REMOTE_ADDR not set', file '%s')
