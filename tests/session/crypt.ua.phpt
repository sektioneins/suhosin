--TEST--
session with encryption using ua
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--ENV--
return <<<END
HTTP_USER_AGENT=test
END;
--INI--
suhosin.session.encrypt=On
suhosin.session.cryptkey=D3F4UL7
suhosin.session.cryptua=On
suhosin.session.cryptdocroot=Off
suhosin.session.cryptraddr=0
suhosin.session.checkraddr=0
--FILE--
<?php
include "sessionhandler.inc";
session_test_start(new CryptCheckSessionHandler("D3F4UL7test"));
$_SESSION['a'] = 'b';


?>
--EXPECTF--
SESSION: encrypted, tag verifies, 32 bytes ciphertext
