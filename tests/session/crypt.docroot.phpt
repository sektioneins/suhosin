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
session_test_start();
$_SESSION['a'] = 'b';


?>
--EXPECTF--
SESSION: NKChb1rdctXd-Acz0uzOYVnJT_J2mxYRVUgSh0w5mlk.
