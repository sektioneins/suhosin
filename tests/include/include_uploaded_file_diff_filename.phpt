--TEST--
Testing include file from $_FILES (but change name a bit)
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.stdout=255
suhosin.executor.include.whitelist=
suhosin.executor.include.blacklist=
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="f1"; filename="filename2"

<?php echo "NO_GOOD/n";
-----------------------------20896060251896012921717172737--
--FILE--
<?php
include "/../../../" . $_FILES['f1']['tmp_name'];
?>
--EXPECTF--
ALERT - Include filename is an uploaded file (attacker 'REMOTE_ADDR not set', file '%s', line 2)