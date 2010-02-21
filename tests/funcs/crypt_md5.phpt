--TEST--
CRYPT_MD5 support
--SKIPIF--
<?php if (CRYPT_MD5 == 0) print 'skip'; ?>
--FILE--
<?php
    echo crypt('rasmuslerdorf', '$1$rasmusle$') . "\n"
?>
--EXPECT--
$1$rasmusle$rISCgZzpwk3UhDidwXvin0

