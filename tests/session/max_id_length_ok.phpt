--TEST--
session id not too long
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.session.max_id_length=32
session.hash_bits_per_character=4
--FILE--
<?php
session_id('12345678901234567890123456789012');
session_start();
echo session_id();
?>
--EXPECTF--
12345678901234567890123456789012