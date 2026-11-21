--TEST--
session with encryption using docroot
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--ENV--
return <<<END
DOCUMENT_ROOT=/var/www
END;
--INI--
suhosin.session.encrypt=On
suhosin.session.cryptkey=D3F4UL7
suhosin.session.cryptua=Off
suhosin.session.cryptdocroot=On
suhosin.session.cryptraddr=0
suhosin.session.checkraddr=0
--FILE--
<?php
include "sessionhandler.inc";
session_test_start(new CryptCheckSessionHandler("D3F4UL7/var/www"));
$_SESSION['a'] = 'b';


?>
--EXPECTF--
SESSION: encrypted, tag verifies, 32 bytes ciphertext
