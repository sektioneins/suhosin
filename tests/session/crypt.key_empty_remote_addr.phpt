--TEST--
session with encryption key empty and REMOTE_ADDR set
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--ENV--
return <<<END
REMOTE_ADDR=127.0.0.1
END;
--INI--
suhosin.session.encrypt=On
suhosin.session.cryptkey=
suhosin.session.cryptua=Off
suhosin.session.cryptdocroot=Off
suhosin.session.cryptraddr=0
suhosin.session.checkraddr=0
--FILE--
<?php
include "sessionhandler.inc";
session_test_start();
$_SESSION['a'] = 'b';


?>
--EXPECTF--
SESSION: j1YTvIOAUqxZMjuJ_ZnHPHWY5XEayycsr7O94aMzmBQ.
