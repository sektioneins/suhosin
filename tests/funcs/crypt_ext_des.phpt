--TEST--
CRYPT_EXT_DES support
--SKIPIF--
<?php if (CRYPT_EXT_DES == 0) print 'skip'; ?>
--FILE--
<?php
    echo crypt('rasmuslerdorf', '_J9..rasm') . "\n"
?>
--EXPECT--
_J9..rasmBYk8r9AiWNc


