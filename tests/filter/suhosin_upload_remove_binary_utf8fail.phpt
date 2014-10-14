--TEST--
Testing: suhosin.upload.remove_binary=On with UTF-8 and allow_utf8=Off
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
file_uploads=1
suhosin.upload.disallow_binary=Off
suhosin.upload.remove_binary=On
suhosin.upload.allow_utf8=Off
max_file_uploads=40
suhosin.upload.max_uploads=40
--SKIPIF--
<?php include('../skipif.inc');
if (ini_get('suhosin.upload.allow_utf8') === FALSE) { die("skip feature not compiled in"); }
?>
--COOKIE--
--GET--
--POST_RAW--
Content-Type: multipart/form-data; boundary=bound
--bound
Content-Disposition: form-data; name="test"; filename="test"

Spaß am Gerät!

--bound--
--FILE--
<?php
var_dump(file_get_contents($_FILES['test']['tmp_name']));
?>
--EXPECTF--
string(13) "Spa am Gert!
"