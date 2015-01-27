--TEST--
suhosin filter action: 302 redirect
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=0
suhosin.log.script=0
suhosin.request.disallow_nul=1
suhosin.filter.action=302,http://example.com/
--SKIPIF--
<?php include('../skipifcli.inc'); ?>
--CGI--
--COOKIE--
x=%00
--FILE--
<?php
echo 'this is wrong!';
?>
--EXPECTHEADERS--
Status: 302 Moved Temporarily
Location: http://example.com/
--EXPECTF--
