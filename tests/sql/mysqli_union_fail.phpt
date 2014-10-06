--TEST--
Mysqli query with UNION protection set to fail
--INI--
extension=mysqli.so
suhosin.sql.bailout_on_error=0
suhosin.sql.comment=0
suhosin.sql.opencomment=0
suhosin.sql.multiselect=0
suhosin.sql.union=2
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
$result = $mysqli->query("SELECT 1 UNION SELECT 2");
echo "mark.";

?>
--EXPECTREGEX--
ALERT - UNION in SQL query.*\)