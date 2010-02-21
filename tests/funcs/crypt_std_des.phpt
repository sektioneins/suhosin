--TEST--
CRYPT_STD_DES support
--SKIPIF--
<?php if (CRYPT_STD_DES == 0) print 'skip'; ?>
--FILE--
<?php
    echo crypt('rasmuslerdorf', 'rl') . "\n"
?>
--EXPECT--
rl.3StKT.4T8M

