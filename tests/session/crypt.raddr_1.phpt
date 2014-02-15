--TEST--
session with encryption using REMOTE_ADDR (cryptraddr=1)
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
suhosin.session.cryptraddr=1
suhosin.session.checkraddr=0
--FILE--
<?php
include "sessionhandler.inc";
session_test_start();
$_SESSION['a'] = 'b';


?>
--EXPECTF--
SESSION: wkiQGgZgWnBFDyCs_4QYD_oaw_m35l_5I35XRg0wX_g.
