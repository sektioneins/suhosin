/*
  +----------------------------------------------------------------------+
  | Suhosin Version 1                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2007 The Hardened-PHP Project                     |
  | Copyright (c) 2007-2015 SektionEins GmbH                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Stefan Esser <sesser@sektioneins.de>                         |
  +----------------------------------------------------------------------+
*/
/*
  $Id: log.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $ 
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_suhosin.h"
#include <fcntl.h>
#include "SAPI.h"
#include "ext/standard/datetime.h"
#include "ext/standard/flock_compat.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#elif defined(PHP_WIN32)
#include "win32/time.h"
#endif

#if defined(PHP_WIN32) || defined(__riscos__) || defined(NETWARE)
#undef AF_UNIX
#endif

#if defined(AF_UNIX)
#include <sys/un.h>
#endif

#define SYSLOG_PATH  "/dev/log"

#include "snprintf.h"

#ifdef PHP_WIN32
static HANDLE log_source = 0;
#endif
#include <sys/file.h>

static char *loglevel2string(int loglevel)
{
	switch (loglevel) {
	    case S_FILES:
		return "FILES";
	    case S_INCLUDE:
		return "INCLUDE";
	    case S_MEMORY:
		return "MEMORY";
	    case S_MISC:
		return "MISC";
	    case S_MAIL:
		return "MAIL";
		case S_SESSION:
		return "SESSION";
	    case S_SQL:
		return "SQL";
	    case S_EXECUTOR:
		return "EXECUTOR";
	    case S_VARS:
		return "VARS";
	    default:
		return "UNKNOWN";    
	}
}

static char *month_names[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

PHP_SUHOSIN_API void suhosin_log(int loglevel, char *fmt, ...)
{
	int s, r, i=0, fd;
	long written, towrite;
	int getcaller=0;
	char *wbuf;
	struct timeval tv;
	time_t now;
	struct tm tm;
#if defined(AF_UNIX)
	struct sockaddr_un saun;
#endif
#ifdef PHP_WIN32
	LPTSTR strs[2];
	unsigned short etype;
	DWORD evid;
#endif
	char buf[5000] = {0};
	char error[5000] = {0};
	char *ip_address;
	char *fname;
	char *alertstring;
	int lineno = 0;
	va_list ap;
	TSRMLS_FETCH();

#if PHP_VERSION_ID >= 50500
	getcaller = (loglevel & S_GETCALLER) == S_GETCALLER;
#endif
	/* remove the S_GETCALLER flag */
	loglevel = loglevel & ~S_GETCALLER;

	SDEBUG("(suhosin_log) loglevel: %d log_syslog: %ld - log_sapi: %ld - log_script: %ld", loglevel, SUHOSIN_G(log_syslog), SUHOSIN_G(log_sapi), SUHOSIN_G(log_script));

	/* dump core if wanted */
	if (SUHOSIN_G(coredump) && loglevel == S_MEMORY) {
		volatile unsigned int *x = 0;
		volatile int y = *x;
	}
	
	if (SUHOSIN_G(log_use_x_forwarded_for)) {
		ip_address = suhosin_getenv("HTTP_X_FORWARDED_FOR", 20 TSRMLS_CC);
		if (ip_address == NULL) {
			ip_address = "X-FORWARDED-FOR not set";
		}
	} else {
		ip_address = suhosin_getenv("REMOTE_ADDR", 11 TSRMLS_CC);
		if (ip_address == NULL) {
			ip_address = "REMOTE_ADDR not set";
		}
	}
	
	
	va_start(ap, fmt);
	ap_php_vsnprintf(error, sizeof(error), fmt, ap);
	va_end(ap);
	if (SUHOSIN_G(log_max_error_length) > 0 && SUHOSIN_G(log_max_error_length) < (sizeof(error) - 4)) {
		memcpy(error + SUHOSIN_G(log_max_error_length), "...", 4);
	}
	while (error[i]) {
		if (error[i] < 32) error[i] = '.';
		i++;
	}
	
	if (SUHOSIN_G(simulation)) {
		alertstring = "ALERT-SIMULATION";
	} else {
		alertstring = "ALERT";
	}
	
	if (zend_is_executing(TSRMLS_C)) {
		zend_execute_data *exdata = EG(current_execute_data);
		if (exdata) {
			if (getcaller && exdata->prev_execute_data && exdata->prev_execute_data->opline && exdata->prev_execute_data->op_array) {
				lineno = exdata->prev_execute_data->opline->lineno;
				fname = (char *)exdata->prev_execute_data->op_array->filename;
			} else if (exdata->opline && exdata->op_array) {
				lineno = exdata->opline->lineno;
				fname = (char *)exdata->op_array->filename;
			} else {
				lineno = 0;
				fname = "[unknown filename]";
			}
		} else {
			lineno = zend_get_executed_lineno(TSRMLS_C);
			fname = (char *)zend_get_executed_filename(TSRMLS_C);
		}
		ap_php_snprintf(buf, sizeof(buf), "%s - %s (attacker '%s', file '%s', line %u)", alertstring, error, ip_address, fname, lineno);
	} else {
		fname = suhosin_getenv("SCRIPT_FILENAME", 15 TSRMLS_CC);
		if (fname==NULL) {
			fname = "unknown";
		}
		ap_php_snprintf(buf, sizeof(buf), "%s - %s (attacker '%s', file '%s')", alertstring, error, ip_address, fname);
	}
			
	/* Syslog-Logging disabled? */
	if (((SUHOSIN_G(log_syslog)|S_INTERNAL) & loglevel)==0) {
		goto log_file;
	}	
	
#if defined(AF_UNIX)
	ap_php_snprintf(error, sizeof(error), "<%u>suhosin[%u]: %s\n", (unsigned int)(SUHOSIN_G(log_syslog_facility)|SUHOSIN_G(log_syslog_priority)),getpid(),buf);

	s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s == -1) {
		goto log_file;
	}
	
	memset(&saun, 0, sizeof(saun));
	saun.sun_family = AF_UNIX;
	strcpy(saun.sun_path, SYSLOG_PATH);
	/*saun.sun_len = sizeof(saun);*/
	
	r = connect(s, (struct sockaddr *)&saun, sizeof(saun));
	if (r) {
		close(s);
    		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s == -1) {
			goto log_file;
		}
	
		memset(&saun, 0, sizeof(saun));
		saun.sun_family = AF_UNIX;
		strcpy(saun.sun_path, SYSLOG_PATH);
		/*saun.sun_len = sizeof(saun);*/

		r = connect(s, (struct sockaddr *)&saun, sizeof(saun));
		if (r) { 
			close(s);
			goto log_file;
		}
	}
	send(s, error, strlen(error), 0);
	
	close(s);
#endif
#ifdef PHP_WIN32
	ap_php_snprintf(error, sizeof(error), "suhosin[%u]: %s", getpid(),buf);

	switch (SUHOSIN_G(log_syslog_priority)) {			/* translate UNIX type into NT type */
		case 1: /*LOG_ALERT:*/
			etype = EVENTLOG_ERROR_TYPE;
			break;
		case 6: /*LOG_INFO:*/
			etype = EVENTLOG_INFORMATION_TYPE;
			break;
		default:
			etype = EVENTLOG_WARNING_TYPE;
	}
	evid = loglevel;
	strs[0] = error;
	/* report the event */
	if (log_source == NULL) {
		log_source = RegisterEventSource(NULL, "Suhosin-" SUHOSIN_EXT_VERSION);
	}
	ReportEvent(log_source, etype, (unsigned short) SUHOSIN_G(log_syslog_priority), evid, NULL, 1, 0, strs, NULL);
	
#endif
log_file:
	/* File-Logging disabled? */
	if ((SUHOSIN_G(log_file) & loglevel)==0) {
		goto log_sapi;
	}
	
	if (!SUHOSIN_G(log_filename) || !SUHOSIN_G(log_filename)[0]) {
		goto log_sapi;
	}
	fd = open(SUHOSIN_G(log_filename), O_CREAT|O_APPEND|O_WRONLY, 0640);
	if (fd == -1) {
	    suhosin_log(S_INTERNAL, "Unable to open logfile: %s", SUHOSIN_G(log_filename));
	    return;
	}

	if (SUHOSIN_G(log_file_time)) {
		gettimeofday(&tv, NULL);
		now = tv.tv_sec;
		php_localtime_r(&now, &tm);
		ap_php_snprintf(error, sizeof(error), "%s %2d %02d:%02d:%02d [%u] %s\n", month_names[tm.tm_mon], tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, getpid(),buf);
	} else {
		ap_php_snprintf(error, sizeof(error), "%s\n", buf);
	}
	towrite = strlen(error);
	wbuf = error;
	php_flock(fd, LOCK_EX);
	while (towrite > 0) {
		written = write(fd, wbuf, towrite);
		if (written < 0) {
			break;
		}
		towrite -= written;
		wbuf += written;
	}
	php_flock(fd, LOCK_UN);
	close(fd);

log_sapi:
	/* SAPI Logging activated? */
	SDEBUG("(suhosin_log) log_syslog: %ld - log_sapi: %ld - log_script: %ld - log_phpscript: %ld", SUHOSIN_G(log_syslog), SUHOSIN_G(log_sapi), SUHOSIN_G(log_script), SUHOSIN_G(log_phpscript));
	if (((SUHOSIN_G(log_sapi)|S_INTERNAL) & loglevel)!=0) {
		sapi_module.log_message(buf TSRMLS_CC);
	}
	if ((SUHOSIN_G(log_stdout) & loglevel)!=0) {
		fprintf(stdout, "%s\n", buf);
	}

/*log_script:*/
	/* script logging activaed? */
	if (((SUHOSIN_G(log_script) & loglevel)!=0) && SUHOSIN_G(log_scriptname)!=NULL) {
		char cmd[8192], *cmdpos, *bufpos;
		FILE *in;
		int space;
		struct stat st;
		
		char *sname = SUHOSIN_G(log_scriptname);
		while (isspace(*sname)) ++sname;
		if (*sname == 0) goto log_phpscript;
		
		if (VCWD_STAT(sname, &st) < 0) {
			suhosin_log(S_INTERNAL, "unable to find logging shell script %s - file dropped", sname);
			goto log_phpscript;
		}
		if (access(sname, X_OK|R_OK) < 0) {
			suhosin_log(S_INTERNAL, "logging shell script %s is not executable - file dropped", sname);
			goto log_phpscript;					
		}
		
		/* TODO: clean up this code to calculate size of output dynamically */
		ap_php_snprintf(cmd, sizeof(cmd) - 20, "%s %s \'", sname, loglevel2string(loglevel));
		space = sizeof(cmd) - strlen(cmd) - 20;
		cmdpos = cmd + strlen(cmd);
		bufpos = buf;
		if (space <= 1) return;
		while (space > 2 && *bufpos) {
			if (*bufpos == '\'') {
				if (space<=5) break;
				*cmdpos++ = '\'';
				*cmdpos++ = '\\';
				*cmdpos++ = '\'';
				*cmdpos++ = '\'';
				bufpos++;
				space-=4;
			} else {
				*cmdpos++ = *bufpos++;
				space--;
			}
		}
		*cmdpos++ = '\'';
		*cmdpos++ = ' ';
		*cmdpos++ = '2';
		*cmdpos++ = '>';
		*cmdpos++ = '&';
		*cmdpos++ = '1';
		*cmdpos = 0;
		
		if ((in=VCWD_POPEN(cmd, "r"))==NULL) {
			suhosin_log(S_INTERNAL, "Unable to execute logging shell script: %s", sname);
			goto log_phpscript;
		}
		/* read and forget the result */
		while (1) {
			int readbytes = fread(cmd, 1, sizeof(cmd), in);
			if (readbytes<=0) {
				break;
			}
			if (strncmp(cmd, "sh: ", 4) == 0) {
				/* assume this is an error */
				suhosin_log(S_INTERNAL, "Error while executing logging shell script: %s", sname);
				pclose(in);
				goto log_phpscript;
			}
		}
		pclose(in);
	}
log_phpscript:
	if ((SUHOSIN_G(log_phpscript) & loglevel)!=0 && EG(in_execution) && SUHOSIN_G(log_phpscriptname) && SUHOSIN_G(log_phpscriptname)[0]) {
		zend_file_handle file_handle;
		zend_op_array *new_op_array;
		zval *result = NULL;
		
		long orig_execution_depth = SUHOSIN_G(execution_depth);
		char *orig_basedir = PG(open_basedir);
		
		char *phpscript = SUHOSIN_G(log_phpscriptname);
SDEBUG("scriptname %s", SUHOSIN_G(log_phpscriptname));				
		if (zend_stream_open(phpscript, &file_handle TSRMLS_CC) == SUCCESS) {
			if (!file_handle.opened_path) {
				file_handle.opened_path = estrndup(phpscript, strlen(phpscript));
			}
			new_op_array = zend_compile_file(&file_handle, ZEND_REQUIRE TSRMLS_CC);
			zend_destroy_file_handle(&file_handle TSRMLS_CC);
			if (new_op_array) {
				HashTable *active_symbol_table = EG(active_symbol_table);
				zval *zerror, *zerror_class;
				
				if (active_symbol_table == NULL) {
					active_symbol_table = &EG(symbol_table);
				}
				EG(return_value_ptr_ptr) = &result;
				EG(active_op_array) = new_op_array;
				
				MAKE_STD_ZVAL(zerror);
				MAKE_STD_ZVAL(zerror_class);
				ZVAL_STRING(zerror, buf, 1);
				ZVAL_LONG(zerror_class, loglevel);

				zend_hash_update(active_symbol_table, "SUHOSIN_ERROR", sizeof("SUHOSIN_ERROR"), (void **)&zerror, sizeof(zval *), NULL);
				zend_hash_update(active_symbol_table, "SUHOSIN_ERRORCLASS", sizeof("SUHOSIN_ERRORCLASS"), (void **)&zerror_class, sizeof(zval *), NULL);
				
				SUHOSIN_G(execution_depth) = 0;
				if (SUHOSIN_G(log_phpscript_is_safe)) {
					PG(open_basedir) = NULL;
				}
				
				zend_execute(new_op_array TSRMLS_CC);
				
				SUHOSIN_G(execution_depth) = orig_execution_depth;
				PG(open_basedir) = orig_basedir;
				
				destroy_op_array(new_op_array TSRMLS_CC);
				efree(new_op_array);

				if (!EG(exception))
				{
					if (EG(return_value_ptr_ptr)) {
						zval_ptr_dtor(EG(return_value_ptr_ptr));
						EG(return_value_ptr_ptr) = NULL;
					}
				}
			} else {
				suhosin_log(S_INTERNAL, "Unable to execute logging PHP script: %s", SUHOSIN_G(log_phpscriptname));
				return;
			}
		} else {
			suhosin_log(S_INTERNAL, "Unable to execute logging PHP script: %s", SUHOSIN_G(log_phpscriptname));
			return;
		}
	}

}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
