--TEST--
SHA256 support
--SKIPIF--
<?php include "../skipif.inc"; ?>
--FILE--
<?php
    echo sha256("") , "\n";
    echo sha256("a"), "\n";
    echo sha256(pack("H*", "bd")), "\n";
    echo sha256(pack("H*", "5fd4")), "\n";
    echo sha256(pack("H*", "b0bd69")), "\n";
    echo sha256(pack("H*", "c98c8e55")), "\n";
    echo sha256(pack("H*", "81a723d966")), "\n";
    echo sha256(pack("H*", "c97a2db566e5")), "\n";
    echo sha256(pack("H*", "f53210aa6ed72e")), "\n";
    echo sha256(pack("H*", "0df1cd526b5a4edd")), "\n";
    echo sha256(pack("H*", "b80233e2c53ab32cc3")), "\n";
    echo sha256(pack("H*", "5d54ed5b52d879aeb5dd")), "\n";
    echo sha256(pack("H*", "df866ecb67ab00515f6247")), "\n";
    echo sha256(pack("H*", "0757de9485a2eaea51126077")), "\n";
    echo sha256(pack("H*", "7c66f5d443c11cfb39dd0aa715")), "\n";
    echo sha256(pack("H*", "329624fed35639fe54957b7d47a9")), "\n";
?>
--EXPECT--
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b
7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788
4096804221093ddccfbf46831490ea63e9e99414858f8d75ff7f642c7ca61803
7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504
7516fb8bb11350df2bf386bc3c33bd0f52cb4c67c6e4745e0488e62c2aea2605
0eb0281b27a4604709b0513b43ad29fdcff9a7a958554abc689d7fe35af703e4
dee684641421d1ba5a65c71f986a117cbb3d619a052a0b3409306c629575c00f
47f527210d6e8f940b5082fec01b7305908fa2b49ea3ae597c19a3986097153c
c60d239cc6da3ad31f4de0c2d58a73ccf3f9279e504fa60ad55a31dcf686f3ca
e0164d90dbfcf173bb88044fac596ccd03b8d247c79907aaa5701767fad7b576
dc990ef3109a7bcf626199db9ab7801213ceb0ad2ee398963b5061e39c05c7b5
c1c9a4daadcc8678835872c7f1f8824376ac7b412e1fc2285069b41afd51397e
6840619417b4d8ecaa7902f8eaf2e82be2638dec97cb7e8fcc377007cc176718
0f5308ff22b828e18bd65afbc427e3c1a678962832519df5f2f803f68f55e10b
