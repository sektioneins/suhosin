--TEST--
suhosin input filter (suhosin.post.max_array_index_length - RFC1867 version)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.max_array_index_length=0
suhosin.post.max_array_index_length=3
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST--
var1[AAA]=1&var2[BBBB]=1&var3[AAA][BBB]=1&var4[AAA][BBBB]=4&var5[AAA][BBB][CCC]=1&var6[AAA][BBBB][CCC]=1
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="var1[AAA]"

1
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="var2[BBBB]"

1
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="var3[AAA][BBB]"

1
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="var4[AAA][BBBB]"

1
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="var5[AAA][BBB][CCC]"

1
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="var6[AAA][BBBB][CCC]"

1
-----------------------------20896060251896012921717172737--
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(3) {
  ["var1"]=>
  array(1) {
    ["AAA"]=>
    string(1) "1"
  }
  ["var3"]=>
  array(1) {
    ["AAA"]=>
    array(1) {
      ["BBB"]=>
      string(1) "1"
    }
  }
  ["var5"]=>
  array(1) {
    ["AAA"]=>
    array(1) {
      ["BBB"]=>
      array(1) {
        ["CCC"]=>
        string(1) "1"
      }
    }
  }
}
ALERT - configured POST variable array index length limit exceeded - dropped variable 'var2[BBBB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured POST variable array index length limit exceeded - dropped variable 'var4[AAA][BBBB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured POST variable array index length limit exceeded - dropped variable 'var6[AAA][BBBB][CCC]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 3 request variables - (0 in GET, 3 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')