--TEST--
Testing: suhosin.upload.remove_binary=On
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
file_uploads=1
suhosin.upload.disallow_binary=Off
suhosin.upload.remove_binary=On
max_file_uploads=40
suhosin.upload.max_uploads=40
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
--GET--
--POST_RAW--
Content-Type: multipart/form-data; boundary=bound
--bound
Content-Disposition: form-data; name="test"; filename="test"

0 
1
2
3
4
5
6
7
8
9	
10

11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32 

--bound--
--FILE--
<?php
var_dump(file_get_contents($_FILES['test']['tmp_name']));
?>
--EXPECTF--
string(94) "0
1
2
3
4
5
6
7
8
9	
10

11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32 
"