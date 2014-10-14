--TEST--
Mysqli query with sub-SELECT
--INI--
extension=mysqli.so
suhosin.sql.bailout_on_error=0
suhosin.sql.comment=0
suhosin.sql.opencomment=0
suhosin.sql.multiselect=1
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
$result = $mysqli->query("SELECT * FROM (SELECT 1)");
flush();
echo "mark.";
?>
--EXPECTREGEX--
ALERT - Multiple SELECT in SQL query.*mark.