<?php

if (PHP_VERSION_ID < 50400) {
	interface SessionHandlerInterface
	{}
}

class GenericSessionHandler implements SessionHandlerInterface
{
	function open($savePath, $sessionName) { return true; }

	function close() { return true; }

	function read($id) { return (string)""; }

	function write($id, $data) { return true; }

	function destroy($id) { return true; }

	function gc($maxlifetime) { return true; }

}
class WriteSessionHandler extends GenericSessionHandler
{
	function write($id, $data)
	{
		echo "SESSION: $data\n";
		return true;
	}
}
class CryptCheckSessionHandler extends GenericSessionHandler
{
	private $material;
	function __construct($material) { $this->material = $material; }
	function write($id, $data)
	{
		include_once dirname(__FILE__) . "/../crypt.inc";
		echo "SESSION: " . suhosin_crypt_check($id, $data, $this->material) . "\n";
		return true;
	}
}
class RemoteAddrSessionHandler extends GenericSessionHandler
{
	## a|s:1:"b"; for session id "suhosintest", cryptkey D3F4UL7, REMOTE_ADDR 127.0.0.1
	function read($id) { return (string)"Ati_E3olSluESjlhfCvZeGxBEgT7TbVtBP5wIooS48MYbL32JMpJk0TyfWmsVBrqOSR4lE40f_dqmUbo6FMjsKOiUH0QglgbG9deCo2Z8Zv4"; }
}


function session_test_start($handler=null) {
	if (!$handler) {
		$handler = new WriteSessionHandler();
	}
	if (PHP_VERSION_ID < 50400) {
		session_set_save_handler(array($handler, "open"), array($handler, "close"), array($handler, "read"), array($handler, "write"), array($handler, "destroy"), array($handler, "gc"));
	} else {
		session_set_save_handler($handler, true);
	}
	session_start();
	return $handler;
}

?>
