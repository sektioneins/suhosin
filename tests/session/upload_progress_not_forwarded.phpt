--TEST--
rfc1867: upload events are not passed on to session upload progress
--DESCRIPTION--
Mitigation for CVE-2026-109619 (and CVE-2026-115560): ext/session's upload
progress handler runs on every multipart request before the request is
initialised and can act on state left behind by an earlier request. PHP's
own mitigation is session.upload_progress.enabled=0. Suhosin's multipart
parser therefore does not forward its events to php_rfc1867_callback.
Even with upload progress switched on in php.ini and cleanup off, no
progress entry may reach the session, while the upload itself still works.
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.script=0
file_uploads=1
session.save_handler=files
session.save_path={PWD}
session.use_cookies=1
session.upload_progress.enabled=1
session.upload_progress.cleanup=0
session.upload_progress.prefix=upload_progress_
session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS
--SKIPIF--
<?php
include('../skipif.inc');
if (!extension_loaded('session')) print 'skip - session extension not available';
?>
--COOKIE--
PHPSESSID=suhosintestuploadprogress
--GET--
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

test
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="file"; filename="file.txt"
Content-Type: text/plain

hello
-----------------------------20896060251896012921717172737--
--FILE--
<?php
session_start();
var_dump($_FILES['file']['name'], $_FILES['file']['error']);
var_dump(isset($_SESSION['upload_progress_test']));
session_destroy();
?>
--CLEAN--
<?php
@unlink(dirname(__FILE__) . '/sess_suhosintestuploadprogress');
?>
--EXPECT--
string(8) "file.txt"
int(0)
bool(false)
