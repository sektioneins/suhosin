--TEST--
session SessionHandler() recursive crash
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
session_set_save_handler(new SessionHandler(), true);
$_SESSION['a'] = 'b';
var_dump($_SESSION);
--EXPECTF--
array(1) {
  ["a"]=>
  string(1) "b"
}
