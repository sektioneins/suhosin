--TEST--
Mysqli connection test without any constraints
--INI--
extension=mysqli.so
suhosin.sql.comment=0
suhosin.sql.bailout_on_error=0
suhosin.sql.comment=0
suhosin.sql.opencomment=0
suhosin.sql.multiselect=0
suhosin.sql.union=0
--SKIPIF--
<?php
include('skipifmysqli.inc');
include('../skipif.inc');
?>
--FILE--
<?php
include('connect.inc');
$mysqli = connect_mysqli_oostyle();
$result = $mysqli->query("SELECT 1 AS A UNION SELECT 2 -- injection");
$rows = $result->fetch_all();
if ($rows !== null && count($rows) == 2) { echo "ok"; }

?>
--EXPECTF--
ok