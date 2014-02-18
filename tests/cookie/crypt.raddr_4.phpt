--TEST--
cookie encryption using REMOTE_ADDR (cryptraddr=4)
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.cookie.encrypt=1
suhosin.cookie.cryptkey=
suhosin.cookie.cryptua=Off
suhosin.cookie.cryptdocroot=Off
suhosin.cookie.cryptraddr=4
suhosin.cookie.checkraddr=0
;suhosin.cookie.cryptlist=
;suhosin.cookie.plainlist=
--ENV--
return <<<END
REMOTE_ADDR=127.0.0.1
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
Set-Cookie: foo=KYNdxYn5b1vujSEplr6YyON2A04YRH0YY4pCZWQDxG8.