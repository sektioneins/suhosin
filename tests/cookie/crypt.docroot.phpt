--TEST--
cookie encryption using document root
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=
suhosin.cookie.cryptua=Off
suhosin.cookie.cryptdocroot=On
suhosin.cookie.cryptraddr=0
suhosin.cookie.checkraddr=0
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--ENV--
return <<<END
DOCUMENT_ROOT=/var/www
END;
--COOKIE--
a=b
--FILE--
<?php
setcookie('foo', 'bar');
$ch = preg_grep("/^Set-Cookie:/", headers_list());
echo join("\n", array_values($ch));
?>
--EXPECTF--
Set-Cookie: foo=CY8CspcGmDQPsap1NqJO1uAjB6fobur1Os5ZCqFGhU8.