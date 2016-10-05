--TEST--
suhosin input filter (suhosin.request.max_array_index_length)
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
suhosin.log.file=255
suhosin.log.file.time=0
suhosin.log.file.name={PWD}/suhosintest.$$.log.tmp
auto_append_file={PWD}/suhosintest.$$.log.tmp
suhosin.request.max_array_index_length=3
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
var1[AAA]=1;var2[BBBB]=1;var3[AAA][BBB]=1;var4[AAA][BBBB]=4;var5[AAA][BBB][CCC]=1;var6[AAA][BBBB][CCC]=1;
--GET--
var1[AAA]=1&var2[BBBB]=1&var3[AAA][BBB]=1&var4[AAA][BBBB]=4&var5[AAA][BBB][CCC]=1&var6[AAA][BBBB][CCC]=1
--POST--
var1[AAA]=1&var2[BBBB]=1&var3[AAA][BBB]=1&var4[AAA][BBBB]=4&var5[AAA][BBB][CCC]=1&var6[AAA][BBBB][CCC]=1
--FILE--
<?php
var_dump($_GET);
var_dump($_POST);
var_dump($_COOKIE);
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
ALERT - configured request variable array index length limit exceeded - dropped variable 'var2[BBBB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured request variable array index length limit exceeded - dropped variable 'var4[AAA][BBBB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured request variable array index length limit exceeded - dropped variable 'var6[AAA][BBBB][CCC]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured request variable array index length limit exceeded - dropped variable 'var2[BBBB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured request variable array index length limit exceeded - dropped variable 'var4[AAA][BBBB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured request variable array index length limit exceeded - dropped variable 'var6[AAA][BBBB][CCC]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured request variable array index length limit exceeded - dropped variable 'var2[BBBB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured request variable array index length limit exceeded - dropped variable 'var4[AAA][BBBB]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - configured request variable array index length limit exceeded - dropped variable 'var6[AAA][BBBB][CCC]' (attacker 'REMOTE_ADDR not set', file '%s')
ALERT - dropped 9 request variables - (3 in GET, 3 in POST, 3 in COOKIE) (attacker 'REMOTE_ADDR not set', file '%s')