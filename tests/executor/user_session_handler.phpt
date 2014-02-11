--TEST--
Testing user session handler functions
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.syslog=0
suhosin.log.script=0
suhosin.log.sapi=2
suhosin.session.encrypt=On
session.save_path=SUHOSIN_TEST_CASE
--FILE--
<?php
   
$GLOBALS['test_array_session'] = array();
$GLOBALS['msg'] = array();

function sess_open($savePath, $sessionName)
{
	$GLOBALS['msg'][] = "open $savePath -> $sessionName";
}
function sess_close()
{
	$GLOBALS['msg'][] = "close";
}
function sess_read($id)
{
	$GLOBALS['msg'][] = "read $id";
	return @$GLOBALS['test_array_session'][$id];
}
function sess_write($id, $data)
{
	$GLOBALS['msg'][] = "write $id - $data";
	$GLOBALS['test_array_session'][$id] = $data;
	return true;
}
function sess_destroy($id)
{
	$GLOBALS['msg'][] = "destroy $id";
}
function sess_gc($lifetime)
{
}
    
session_set_save_handler ( "sess_open" , "sess_close" , "sess_read" , "sess_write" , "sess_destroy" , "sess_gc" );
session_id(md5("testsession1"));
session_start();

$_SESSION['test1'] = "test";
$_SESSION['test2'] = 12345;
$_SESSION['test3'] = array();
$_SESSION['test4'] = new StdClass();

session_write_close();

session_start();

var_dump($_SESSION);
var_dump($msg);

?>
--EXPECTF--
array(4) {
  ["test1"]=>
  string(4) "test"
  ["test2"]=>
  int(12345)
  ["test3"]=>
  array(0) {
  }
  ["test4"]=>
  object(stdClass)#1 (0) {
  }
}
array(6) {
  [0]=>
  string(35) "open SUHOSIN_TEST_CASE -> PHPSESSID"
  [1]=>
  string(37) "read 4cdacd154c45b08c35d83f3b514eddab"
  [2]=>
  string(%d) "write 4cdacd154c45b08c35d83f3b514eddab - %s"
  [3]=>
  string(5) "close"
  [4]=>
  string(35) "open SUHOSIN_TEST_CASE -> PHPSESSID"
  [5]=>
  string(37) "read 4cdacd154c45b08c35d83f3b514eddab"
}
