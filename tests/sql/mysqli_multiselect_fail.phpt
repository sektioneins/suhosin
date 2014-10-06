--TEST--
Mysqli query with multiple SELECT statements set to fail
--INI--
extension=mysqli.so
suhosin.sql.bailout_on_error=0
suhosin.sql.comment=0
suhosin.sql.opencomment=0
suhosin.sql.multiselect=2
suhosin.sql.union=0
suhosin.log.stdout=32
--SKIPIF--
<?php
include('skipifmysqli.inc');
include('../skipif.inc');
?>
--FILE--
<?php
include('connect.inc');
$mysqli = connect_mysqli_oostyle();
$result = $mysqli->query("SELECT 1; SELECT 2");
flush();
echo "mark.";
?>
--EXPECTREGEX--
ALERT - Multiple SELECT in SQL query.*\)