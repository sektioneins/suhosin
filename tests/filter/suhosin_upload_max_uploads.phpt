--TEST--
suhosin.upload.max_uploads
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.post.max_vars=5
file_uploads=1
suhosin.upload.max_uploads=3
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="A"; filename="A"

A
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="B"; filename="B"

B
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="C"; filename="C"

C
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="D"; filename="D"

D
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="E"; filename="E"

E
-----------------------------20896060251896012921717172737--
--FILE--
<?php
var_dump($_FILES);
?>
--EXPECTF--
array(3) {
  ["A"]=>
  array(5) {
    ["name"]=>
    string(1) "A"
    ["type"]=>
    string(0) ""
    ["tmp_name"]=>
    string(%d) "%s"
    ["error"]=>
    int(0)
    ["size"]=>
    int(1)
  }
  ["B"]=>
  array(5) {
    ["name"]=>
    string(1) "B"
    ["type"]=>
    string(0) ""
    ["tmp_name"]=>
    string(%d) "%s"
    ["error"]=>
    int(0)
    ["size"]=>
    int(1)
  }
  ["C"]=>
  array(5) {
    ["name"]=>
    string(1) "C"
    ["type"]=>
    string(0) ""
    ["tmp_name"]=>
    string(%d) "%s"
    ["error"]=>
    int(0)
    ["size"]=>
    int(1)
  }
}
ALERT - configured fileupload limit exceeded - file dropped (attacker 'REMOTE_ADDR not set', file '%s')