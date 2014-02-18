--TEST--
PHPSESSID session id too long
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--INI--
suhosin.session.max_id_length=32
session.hash_bits_per_character=4
--COOKIE--
PHPSESSID=123456789012345678901234567890123;
--FILE--
<?php
session_start();
echo strlen(session_id());
?>
--EXPECTF--
32