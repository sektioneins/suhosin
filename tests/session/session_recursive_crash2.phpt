--TEST--
session user handler recursive crash - issue #60
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
$foo = "";

class MySessionHandlerA implements SessionHandlerInterface
{
	public function close() {}
	public function destroy($session_id) {}
	public function gc($maxlifetime) {}
	public function open($save_path, $name) { global $foo; $foo .= "A\n"; }
	public function read($session_id ) {}
	public function write($session_id, $session_data) {}
}

session_set_save_handler(new MySessionHandlerA(), true);
session_start();
session_destroy();

//

class MySessionHandlerB extends MySessionHandlerA
{
	public function open($save_path, $name) { global $foo; $foo .= "B\n"; }
}

session_set_save_handler(new MySessionHandlerB(), true);
session_start();
session_destroy();

//

class MySessionHandlerC extends MySessionHandlerA
{
	public function open($save_path, $name) { global $foo; $foo .= "C\n"; }
}

session_set_save_handler(new MySessionHandlerC(), true);
session_start();
session_destroy();


echo $foo;
--EXPECTF--
A
B
C
