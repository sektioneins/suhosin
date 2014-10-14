--TEST--
Mysqli query with SQL open comment protection (/*...) set to fail
--INI--
extension=mysqli.so
suhosin.sql.bailout_on_error=0
suhosin.sql.comment=0
suhosin.sql.opencomment=2
suhosin.sql.multiselect=0
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
$result = $mysqli->query("SELECT 1 /*");
flush();
echo "mark.";
?>
--EXPECTREGEX--
ALERT - Open comment in SQL query.*\)