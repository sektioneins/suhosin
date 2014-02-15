--TEST--
session with encryption using REMOTE_ADDR (cryptraddr=3)
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--ENV--
return <<<END
REMOTE_ADDR=127.0.0.1
END;
--INI--
suhosin.session.encrypt=On
suhosin.session.cryptkey=D3F4UL7
suhosin.session.cryptua=Off
suhosin.session.cryptdocroot=Off
suhosin.session.cryptraddr=3
suhosin.session.checkraddr=0
--FILE--
<?php
include "sessionhandler.inc";
session_test_start();
$_SESSION['a'] = 'b';


?>
--EXPECTF--
SESSION: 6kLKLrgCmlOuEPXPON_K5SWHLuIbHdLsh4MJ0QtTFj8.
