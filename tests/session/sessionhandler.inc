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
class RemoteAddrSessionHandler extends GenericSessionHandler
{
	## key empty and REMOTE_ADDR set to 127.0.0.1
	function read($id) { return (string)"j1YTvIOAUqxZMjuJ_ZnHPHWY5XEayycsr7O94aMzmBQ."; }
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
