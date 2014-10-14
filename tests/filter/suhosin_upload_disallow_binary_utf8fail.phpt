--TEST--
Testing: suhosin.upload.disallow_binary=On with UTF-8 and allow_utf8=Off
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
file_uploads=1
suhosin.upload.disallow_binary=On
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
    string(0) ""
    ["error"]=>
    int(8)
    ["size"]=>
    int(0)
  }
}
ALERT - uploaded file contains binary data - file dropped (attacker 'REMOTE_ADDR not set', file '%s')
