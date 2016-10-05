--TEST--
suhosin input filter (suhosin.get.max_array_depth)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.max_array_depth=0
suhosin.get.max_array_depth=4
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
var1[]=1&var2[][]=2&var3[][][]=3&var4[][][][]=4&var5[][][][][]=5&var6[][][][][][]=6&
--POST--
--FILE--
<?php
var_dump($_GET);
?>
--EXPECTF--
array(4) {
  ["var1"]=>
  array(1) {
    [0]=>
    string(1) "1"
  }
  ["var2"]=>
  array(1) {
    [0]=>
    array(1) {
      [0]=>
      string(1) "2"
    }
  }
  ["var3"]=>
  array(1) {
    [0]=>
    array(1) {
      [0]=>
      array(1) {
        [0]=>
        string(1) "3"
      }
    }
  }
  ["var4"]=>
  array(1) {
    [0]=>
    array(1) {
      [0]=>
      array(1) {
        [0]=>
        array(1) {
          [0]=>
          string(1) "4"
        }
      }
    }
  }
}
ALERT - configured GET variable array depth limit exceeded - dropped variable 'var5[][][][][]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured GET variable array depth limit exceeded - dropped variable 'var6[][][][][][]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 2 request variables - (2 in GET, 0 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
