--TEST--
suhosin file upload filter (array index whitelist)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
file_uploads=1
suhosin.request.array_index_blacklist=ABC
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="fn[foo][bar]"

ok
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="fn[foo][BAR]"

bad
-----------------------------20896060251896012921717172737--
--FILE--
<?php
var_dump($_POST);
?>
--EXPECTF--
array(1) {
  ["fn"]=>
  array(1) {
    ["foo"]=>
    array(1) {
      ["bar"]=>
      string(2) "ok"
    }
  }
}
ALERT - array index contains blacklisted characters - dropped variable 'fn[foo][BAR]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 1 request variables - (0 in GET, 1 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
