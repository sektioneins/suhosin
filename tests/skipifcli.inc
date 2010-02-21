<?php 
if (php_sapi_name()=='cli') { 
	print 'skip - SAPI == cli'; 
} else {
if(!extension_loaded("suhosin")) 
	print "skip - SUHOSIN extension not available"; 
}
?>
