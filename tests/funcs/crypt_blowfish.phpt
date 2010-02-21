--TEST--
CRYPT_BLOWFISH support
--SKIPIF--
<?php include "../skipif.inc"; ?>
--FILE--
<?php
    var_dump(CRYPT_BLOWFISH);
    echo crypt('rasmuslerdorf', '$2a$07$rasmuslerd...........$') . "\n";
?>
--EXPECT--
int(1)
$2a$07$rasmuslerd............nIdrcHdxcUxWomQX9j6kvERCFjTg7Ra

