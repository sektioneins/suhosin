--TEST--
Testing: suhosin.upload.disallow_elf=On
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
file_uploads=1
suhosin.upload.disallow_elf=On
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="A"; filename="A"

ELFABCDEFGHIJKLMN
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="B"; filename="B"

XELFABCDEFGHIJKLMN
-----------------------------20896060251896012921717172737--
--FILE--
<?php
var_dump($_FILES);
?>
--EXPECTF--
array(2) {
  ["A"]=>
  array(5) {
    ["name"]=>
    string(1) "A"
    ["type"]=>
    string(0) ""
    ["tmp_name"]=>
    string(0) ""
    ["error"]=>
    int(8)
    ["size"]=>
    int(0)
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
    int(18)
  }
}
ALERT - uploaded file is an ELF executable - file dropped (attacker 'REMOTE_ADDR not set', file '%s')