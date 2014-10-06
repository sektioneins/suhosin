--TEST--
suhosin rfc1867 file upload filter (suhosin.post.max_vars)
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
upload_max_filesize=1024
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="A"

A
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="B"

B
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="C"

C
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="D"

D
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="E"

E
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="F"

F
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="G"

G
-----------------------------20896060251896012921717172737--
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
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
ALERT - configured POST variable limit exceeded - dropped variable 'F' - all further POST variables are dropped (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 2 request variables - (0 in GET, 2 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
