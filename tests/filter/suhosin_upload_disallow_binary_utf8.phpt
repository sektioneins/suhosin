--TEST--
Testing: suhosin.upload.disallow_binary=On with UTF-8
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
file_uploads=1
suhosin.upload.disallow_binary=On
suhosin.upload.allow_utf8=On
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
var_dump($_FILES);
?>
--EXPECTF--
array(1) {
  ["test"]=>
  array(5) {
    ["name"]=>
    string(4) "test"
    ["type"]=>
    string(0) ""
    ["tmp_name"]=>
    string(%d) "%s"
    ["error"]=>
    int(0)
    ["size"]=>
    int(17)
  }
}
