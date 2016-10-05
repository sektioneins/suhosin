--TEST--
suhosin input filter (suhosin.post.max_array_depth)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.max_array_depth=0
suhosin.post.max_array_depth=4
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST--
var1[]=1&var2[][]=2&var3[][][]=3&var4[][][][]=4&var5[][][][][]=5&var6[][][][][][]=6&
--FILE--
<?php
var_dump($_POST);
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
ALERT - configured POST variable array depth limit exceeded - dropped variable 'var5[][][][][]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured POST variable array depth limit exceeded - dropped variable 'var6[][][][][][]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 2 request variables - (0 in GET, 2 in POST, 0 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')
