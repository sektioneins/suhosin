/*
  +----------------------------------------------------------------------+
  | Suhosin Version 1                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2007 The Hardened-PHP Project                     |
  | Copyright (c) 2007-2010 SektionEins GmbH                             |
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

/* $Id: suhosin.c,v 1.2 2007-11-28 16:01:50 sesser Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_extensions.h"
#include "ext/standard/info.h"
#include "php_syslog.h"
#include "php_suhosin.h"
#include "zend_llist.h"
#include "zend_operators.h"
#include "SAPI.h"
#include "php_logos.h"
#include "suhosin_logo.h"
#include "ext/standard/php_string.h"
#include "ext/standard/url.h"
#include "ext/standard/base64.h"

ZEND_DECLARE_MODULE_GLOBALS(suhosin)

static zend_llist_position lp = NULL;
static int (*old_startup)(zend_extension *extension) = NULL;
static zend_extension *ze = NULL;

static int suhosin_module_startup(zend_extension *extension);
static void suhosin_shutdown(zend_extension *extension);


static void (*orig_op_array_ctor)(zend_op_array *op_array) = NULL;
static void (*orig_op_array_dtor)(zend_op_array *op_array) = NULL;
static void (*orig_module_shutdown)(zend_extension *extension) = NULL;
static int (*orig_module_startup)(zend_extension *extension) = NULL;


static void suhosin_op_array_ctor(zend_op_array *op_array);
static void suhosin_op_array_dtor(zend_op_array *op_array);

STATIC zend_extension suhosin_zend_extension_entry = {
	"Suhosin",
	SUHOSIN_EXT_VERSION,
	"SektionEins GmbH",
	"http://www.suhosin.org",
	"Copyright (c) 2007-2010",
	suhosin_module_startup,
	suhosin_shutdown,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	suhosin_op_array_ctor,
	suhosin_op_array_dtor,
	
	STANDARD_ZEND_EXTENSION_PROPERTIES
};

static void suhosin_op_array_ctor(zend_op_array *op_array)
{
	TSRMLS_FETCH();

	if (suhosin_zend_extension_entry.resource_number != -1) {
	
		unsigned long suhosin_flags = 0;
		
		if (SUHOSIN_G(in_code_type) == SUHOSIN_EVAL) {
			suhosin_flags |= SUHOSIN_FLAG_CREATED_BY_EVAL;
		}
		
		op_array->reserved[suhosin_zend_extension_entry.resource_number] = (void *)suhosin_flags;
		
	}
}



static void suhosin_op_array_dtor(zend_op_array *op_array)
{
	if (suhosin_zend_extension_entry.resource_number != -1) {
		op_array->reserved[suhosin_zend_extension_entry.resource_number] = NULL;
	}
}

/* Stealth Mode functions */

static void stealth_op_array_ctor(zend_op_array *op_array)
{
	if (orig_op_array_ctor != NULL) {
        orig_op_array_ctor(op_array);
    }
	suhosin_op_array_ctor(op_array);
}

static void stealth_op_array_dtor(zend_op_array *op_array)
{
	if (orig_op_array_dtor != NULL) {
	    orig_op_array_dtor(op_array);
    }
	suhosin_op_array_dtor(op_array);
}

static int stealth_module_startup(zend_extension *extension)
{
	int r = orig_module_startup == NULL ? SUCCESS : orig_module_startup(extension);
	suhosin_module_startup(extension);
    return r;
}

static void stealth_module_shutdown(zend_extension *extension)
{
	if (orig_module_shutdown != NULL) {
	    orig_module_shutdown(extension);
    }
	suhosin_shutdown(extension);
}


static int suhosin_module_startup(zend_extension *extension)
{
	zend_module_entry *module_entry_ptr;
	int resid;
	TSRMLS_FETCH();
	
/*	zend_register_module(&suhosin_module_entry TSRMLS_CC); */
	
	if (zend_hash_find(&module_registry, "suhosin", sizeof("suhosin"), (void **)&module_entry_ptr)==SUCCESS) {
		
		if (extension) {
		    extension->handle = module_entry_ptr->handle;
		} else {
		    zend_extension ext;
		    ext = suhosin_zend_extension_entry;
		    ext.handle = module_entry_ptr->handle;
		    /*
		    zend_llist_add_element(&zend_extensions, &ext);
		    extension = zend_llist_get_last(&zend_extensions);
		    */
		    extension = &suhosin_zend_extension_entry;
		}
		module_entry_ptr->handle = NULL;

	} else {
		return FAILURE;
	}



	if (SUHOSIN_G(apc_bug_workaround)) {
		resid = zend_get_resource_handle(extension);
	}
	resid = zend_get_resource_handle(extension);
	suhosin_zend_extension_entry.resource_number = resid;

	suhosin_hook_treat_data();
	suhosin_hook_post_handlers(TSRMLS_C);
	suhosin_aes_gentables();
	suhosin_hook_register_server_variables();
	suhosin_hook_header_handler();
	suhosin_hook_execute(TSRMLS_C);
	suhosin_hook_session(TSRMLS_C);


	return SUCCESS;
}


static void suhosin_shutdown(zend_extension *extension)
{
	suhosin_unhook_execute();
	suhosin_unhook_header_handler();
    
    if (ze != NULL) {
	    ze->startup = orig_module_startup;
	    ze->shutdown = orig_module_shutdown;
	    ze->op_array_ctor = orig_op_array_ctor;
	    ze->op_array_dtor = orig_op_array_dtor;
    }
    
}


static int suhosin_startup_wrapper(zend_extension *ext)
{
	int res;
	zend_extension *ex = &suhosin_zend_extension_entry;
	char *new_info;
	int new_info_length;
	TSRMLS_FETCH();
	
	/* Ugly but working hack */
	new_info_length = sizeof("%s\n    with %s v%s, %s, by %s\n")
                        + strlen(ext->author)
						+ strlen(ex->name)
						+ strlen(ex->version)
						+ strlen(ex->copyright)
						+ strlen(ex->author);

	new_info = (char *) malloc(new_info_length+1);
	sprintf(new_info, "%s\n    with %s v%s, %s, by %s", ext->author, ex->name, ex->version, ex->copyright, ex->author);
	ext->author = new_info;

	ze->startup = old_startup;
	
	/* Stealth Mode */
	orig_module_startup = ze->startup;
	orig_module_shutdown = ze->shutdown;
	orig_op_array_ctor = ze->op_array_ctor;
	orig_op_array_dtor = ze->op_array_dtor;

    /*if (SUHOSIN_G(stealth) != 0) {*/
	    ze->startup = stealth_module_startup;
	    ze->shutdown = stealth_module_shutdown;
	    ze->op_array_ctor = stealth_op_array_ctor;
	    ze->op_array_dtor = stealth_op_array_dtor;
    /*}*/
	
	res = old_startup(ext);

/*    ex->name = NULL; 
    ex->author = NULL;
    ex->copyright = NULL;
    ex->version = NULL;*/

    /*zend_extensions.head=NULL;*/

	suhosin_module_startup(NULL);
    
	
	return res;
}

/*static zend_extension_version_info extension_version_info = { ZEND_EXTENSION_API_NO, ZEND_VERSION, ZTS_V, ZEND_DEBUG };*/

#define PERDIR_CHECK(upper, lower) \
    if (!SUHOSIN_G(lower ## _perdir) && stage == ZEND_INI_STAGE_HTACCESS) { \
        return FAILURE; \
    } 

#define LOG_PERDIR_CHECK() PERDIR_CHECK(LOG, log)
#define EXEC_PERDIR_CHECK() PERDIR_CHECK(EXEC, exec)
#define MISC_PERDIR_CHECK() PERDIR_CHECK(MISC, misc)
#define GET_PERDIR_CHECK() PERDIR_CHECK(GET, get)
#define POST_PERDIR_CHECK() PERDIR_CHECK(POST, post)
#define COOKIE_PERDIR_CHECK() PERDIR_CHECK(COOKIE, cookie)
#define REQUEST_PERDIR_CHECK() PERDIR_CHECK(REQUEST, request)
#define UPLOAD_PERDIR_CHECK() PERDIR_CHECK(UPLOAD, upload)
#define SQL_PERDIR_CHECK() PERDIR_CHECK(SQL, sql)

#define ZEND_INI_MH_PASSTHRU entry, new_value, new_value_length, mh_arg1, mh_arg2, mh_arg3, stage TSRMLS_CC


static ZEND_INI_MH(OnUpdateSuhosin_perdir)
{
        char *tmp;

	if (SUHOSIN_G(perdir)) {
    		pefree(SUHOSIN_G(perdir), 1);
	}
	SUHOSIN_G(perdir) = NULL;
    
        /* Initialize the perdir flags */
        SUHOSIN_G(log_perdir) = 0;
        SUHOSIN_G(exec_perdir) = 0;
        SUHOSIN_G(get_perdir) = 0;
        SUHOSIN_G(cookie_perdir) = 0;
        SUHOSIN_G(post_perdir) = 0;
        SUHOSIN_G(request_perdir) = 0;
        SUHOSIN_G(sql_perdir) = 0;
        SUHOSIN_G(upload_perdir) = 0;
        SUHOSIN_G(misc_perdir) = 0;
    
	if (new_value == NULL) {
		return SUCCESS;
	}
	
        tmp = SUHOSIN_G(perdir) = pestrdup(new_value,1);
        
        /* trim the whitespace */
        while (isspace(*tmp)) tmp++;
        
        /* should we deactivate perdir completely? */
        if (*tmp == 0 || *tmp == '0') {
            return SUCCESS;
        }
        
        /* no deactivation so check the flags */
        while (*tmp) {
            switch (*tmp) {
                case 'l':
                case 'L':
                    SUHOSIN_G(log_perdir) = 1;
                    break;
                case 'e':
                case 'E':
                    SUHOSIN_G(exec_perdir) = 1;
                    break;
                case 'g':
                case 'G':
                    SUHOSIN_G(get_perdir) = 1;
                    break;
                case 'c':
                case 'C':
                    SUHOSIN_G(cookie_perdir) = 1;
                    break;
                case 'p':
                case 'P':
                    SUHOSIN_G(post_perdir) = 1;
                    break;
                case 'r':
                case 'R':
                    SUHOSIN_G(request_perdir) = 1;
                    break;
                case 's':
                case 'S':
                    SUHOSIN_G(sql_perdir) = 1;
                    break;
                case 'u':
                case 'U':
                    SUHOSIN_G(upload_perdir) = 1;
                    break;
                case 'm':
                case 'M':
                    SUHOSIN_G(misc_perdir) = 1;
                    break;
            }
            tmp++;
        }        
	return SUCCESS;
}

#define dohandler(handler, name, upper, lower) \
    static ZEND_INI_MH(OnUpdate ## name ## handler) \
    { \
        PERDIR_CHECK(upper, lower) \
        return OnUpdate ## handler (ZEND_INI_MH_PASSTHRU); \
    } \

#define dohandlers(name, upper, lower) \
    dohandler(Bool, name, upper, lower) \
    dohandler(String, name, upper, lower) \
    dohandler(Long, name, upper, lower) \

dohandlers(Log, LOG, log)
dohandlers(Exec, EXEC, exec)
dohandlers(Misc, MISC, misc)
dohandlers(Get, GET, get)
dohandlers(Post, POST, post)
dohandlers(Cookie, COOKIE, cookie)
dohandlers(Request, REQUEST, request)
dohandlers(Upload, UPLOAD, upload)
dohandlers(SQL, SQL, sql)

static ZEND_INI_MH(OnUpdateSuhosin_log_syslog)
{
    LOG_PERDIR_CHECK()
	if (!new_value) {
		SUHOSIN_G(log_syslog) = (S_ALL & ~S_SQL) | S_MEMORY;
	} else {
		SUHOSIN_G(log_syslog) = atoi(new_value) | S_MEMORY;
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_syslog_facility)
{
    LOG_PERDIR_CHECK()
	if (!new_value) {
		SUHOSIN_G(log_syslog_facility) = LOG_USER;
	} else {
		SUHOSIN_G(log_syslog_facility) = atoi(new_value);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_syslog_priority)
{
    LOG_PERDIR_CHECK()
	if (!new_value) {
		SUHOSIN_G(log_syslog_priority) = LOG_ALERT;
	} else {
		SUHOSIN_G(log_syslog_priority) = atoi(new_value);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_sapi)
{
    LOG_PERDIR_CHECK()
	if (!new_value) {
		SUHOSIN_G(log_sapi) = (S_ALL & ~S_SQL);
	} else {
		SUHOSIN_G(log_sapi) = atoi(new_value);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_script)
{
    LOG_PERDIR_CHECK()
	if (!new_value) {
		SUHOSIN_G(log_script) = S_ALL & ~S_MEMORY;
	} else {
		SUHOSIN_G(log_script) = atoi(new_value) & (~S_MEMORY) & (~S_INTERNAL);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_scriptname)
{
    LOG_PERDIR_CHECK()
	if (SUHOSIN_G(log_scriptname)) {
		pefree(SUHOSIN_G(log_scriptname),1);
	}
    SUHOSIN_G(log_scriptname) = NULL;
	if (new_value) {
		SUHOSIN_G(log_scriptname) = pestrdup(new_value,1);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_phpscript)
{
    LOG_PERDIR_CHECK()
	if (!new_value) {
		SUHOSIN_G(log_phpscript) = S_ALL & ~S_MEMORY;
	} else {
		SUHOSIN_G(log_phpscript) = atoi(new_value) & (~S_MEMORY) & (~S_INTERNAL);
	}
	return SUCCESS;
}
static ZEND_INI_MH(OnUpdateSuhosin_log_file)
{
    LOG_PERDIR_CHECK()
	if (!new_value) {
		SUHOSIN_G(log_file) = S_ALL & ~S_MEMORY;
	} else {
		SUHOSIN_G(log_file) = atoi(new_value) & (~S_MEMORY) & (~S_INTERNAL);
	}
	return SUCCESS;
}

static void parse_list(HashTable **ht, char *list, zend_bool lc)
{
	char *s = NULL, *e, *val;
	unsigned long dummy = 1;
	
	if (list == NULL) {
list_destroy:
		if (*ht) {
			zend_hash_destroy(*ht);
			pefree(*ht, 1);
		}
		*ht = NULL;
		return;
	}
	while (*list == ' ' || *list == '\t') list++;
	if (*list == 0) {
		goto list_destroy;
	}
	
	*ht = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(*ht, 5, NULL, NULL, 1);
	
	if (lc) {
        val = suhosin_str_tolower_dup(list, strlen(list));
    } else {
        val = estrndup(list, strlen(list));
    }
	e = val;
	
	while (*e) {
		switch (*e) {
			case ' ':
			case ',':
				if (s) {
					*e = '\0';
					zend_hash_add(*ht, s, e-s+1, &dummy, sizeof(unsigned long), NULL);
					s = NULL;
				}
				break;
			default:
				if (!s) {
					s = e;
				}
				break;
		}
		e++;
	}
	if (s) {
		zend_hash_add(*ht, s, e-s+1, &dummy, sizeof(unsigned long), NULL);
	}
	efree(val);

}

static ZEND_INI_MH(OnUpdate_include_blacklist)
{
    EXEC_PERDIR_CHECK()
	parse_list(&SUHOSIN_G(include_blacklist), new_value, 1);
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_include_whitelist)
{
    EXEC_PERDIR_CHECK()
	parse_list(&SUHOSIN_G(include_whitelist), new_value, 1);
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_func_blacklist)
{
    EXEC_PERDIR_CHECK()
	parse_list(&SUHOSIN_G(func_blacklist), new_value, 1);
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_func_whitelist)
{
    EXEC_PERDIR_CHECK()
	parse_list(&SUHOSIN_G(func_whitelist), new_value, 1);
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_eval_blacklist)
{
    EXEC_PERDIR_CHECK()
	parse_list(&SUHOSIN_G(eval_blacklist), new_value, 1);
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_eval_whitelist)
{
    EXEC_PERDIR_CHECK()
	parse_list(&SUHOSIN_G(eval_whitelist), new_value, 1);
	return SUCCESS;
}


static ZEND_INI_MH(OnUpdate_cookie_cryptlist)
{
	parse_list(&SUHOSIN_G(cookie_cryptlist), new_value, 0);
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdate_cookie_plainlist)
{
	parse_list(&SUHOSIN_G(cookie_plainlist), new_value, 0);
	return SUCCESS;
}

/* {{{ proto void suhosin_register_cookie_variable(char *var, zval *val, zval *track_vars_array TSRMLS_DC)
   Registers a cookie in the RAW cookie array */
static void suhosin_register_cookie_variable(char *var, zval *val, zval *track_vars_array TSRMLS_DC)
{
	char *p = NULL;
	char *ip;		/* index pointer */
	char *index, *escaped_index = NULL;
	int var_len, index_len;
	zval *gpc_element, **gpc_element_p;
	zend_bool is_array = 0;
	HashTable *symtable1 = NULL;

	assert(var != NULL);
	
	symtable1 = Z_ARRVAL_P(track_vars_array);

	/*
	 * Prepare variable name
	 */

	/* ignore leading spaces in the variable name */
	while (*var && *var==' ') {
		var++;
	}

	/* ensure that we don't have spaces or dots in the variable name (not binary safe) */
	for (p = var; *p; p++) {
		if (*p == ' ' || *p == '.') {
			*p='_';
		} else if (*p == '[') {
			is_array = 1;
			ip = p;
			*p = 0;
			break;
		}
	}
	var_len = p - var;

	if (var_len==0) { /* empty variable name, or variable name with a space in it */
		zval_dtor(val);
		return;
	}

	index = var;
	index_len = var_len;

	if (is_array) {
		while (1) {
			char *index_s;
			int new_idx_len = 0;

			ip++;
			index_s = ip;
			if (isspace(*ip)) {
				ip++;
			}
			if (*ip==']') {
				index_s = NULL;
			} else {
				ip = strchr(ip, ']');
				if (!ip) {
					/* PHP variables cannot contain '[' in their names, so we replace the character with a '_' */
					*(index_s - 1) = '_';

					index_len = var_len = 0;
					if (index) {
						index_len = var_len = strlen(index);
					}
					goto plain_var;
					return;
				}
				*ip = 0;
				new_idx_len = strlen(index_s);	
			}

			if (!index) {
				MAKE_STD_ZVAL(gpc_element);
				array_init(gpc_element);
				zend_hash_next_index_insert(symtable1, &gpc_element, sizeof(zval *), (void **) &gpc_element_p);
			} else {
				if (PG(magic_quotes_gpc) && (index != var)) {
					/* no need to addslashes() the index if it's the main variable name */
					escaped_index = php_addslashes(index, index_len, &index_len, 0 TSRMLS_CC);
				} else {
					escaped_index = index;
				}
				if (zend_symtable_find(symtable1, escaped_index, index_len + 1, (void **) &gpc_element_p) == FAILURE
					|| Z_TYPE_PP(gpc_element_p) != IS_ARRAY) {
					MAKE_STD_ZVAL(gpc_element);
					array_init(gpc_element);
					zend_symtable_update(symtable1, escaped_index, index_len + 1, &gpc_element, sizeof(zval *), (void **) &gpc_element_p);
				}
				if (index != escaped_index) {
					efree(escaped_index);
				}
			}
			symtable1 = Z_ARRVAL_PP(gpc_element_p);
			/* ip pointed to the '[' character, now obtain the key */
			index = index_s;
			index_len = new_idx_len;

			ip++;
			if (*ip == '[') {
				is_array = 1;
				*ip = 0;
			} else {
				goto plain_var;
			}
		}
	} else {
plain_var:
		MAKE_STD_ZVAL(gpc_element);
		gpc_element->value = val->value;
		Z_TYPE_P(gpc_element) = Z_TYPE_P(val);
		if (!index) {
			zend_hash_next_index_insert(symtable1, &gpc_element, sizeof(zval *), (void **) &gpc_element_p);
		} else {
			if (PG(magic_quotes_gpc)) { 
				escaped_index = php_addslashes(index, index_len, &index_len, 0 TSRMLS_CC);
			} else {
				escaped_index = index;
			}
			/* 
			 * According to rfc2965, more specific paths are listed above the less specific ones.
			 * If we encounter a duplicate cookie name, we should skip it, since it is not possible
			 * to have the same (plain text) cookie name for the same path and we should not overwrite
			 * more specific cookies with the less specific ones.
			 */
            if (zend_symtable_exists(symtable1, escaped_index, index_len + 1)) {
				zval_ptr_dtor(&gpc_element);
			} else {
				zend_symtable_update(symtable1, escaped_index, index_len + 1, &gpc_element, sizeof(zval *), (void **) &gpc_element_p);
			}
			if (escaped_index != index) {
				efree(escaped_index);
			}
		}
	}
}
/* }}} */

static void suhosin_register_cookie_variable_safe(char *var, char *strval, int str_len, zval *track_vars_array TSRMLS_DC)
{
	zval new_entry;
	assert(strval != NULL);
	
	/* Prepare value */
	Z_STRLEN(new_entry) = str_len;
	if (PG(magic_quotes_gpc)) {
		Z_STRVAL(new_entry) = php_addslashes(strval, Z_STRLEN(new_entry), &Z_STRLEN(new_entry), 0 TSRMLS_CC);
	} else {
		Z_STRVAL(new_entry) = estrndup(strval, Z_STRLEN(new_entry));
	}
	Z_TYPE(new_entry) = IS_STRING;

	suhosin_register_cookie_variable(var, &new_entry, track_vars_array TSRMLS_CC);
}


/* {{{ proto string suhosin_encrypt_cookie(string name, string value)
   Encrypts a cookie value according to current cookie encrpytion setting */
static PHP_FUNCTION(suhosin_encrypt_cookie)
{
	char *name, *value;
	int name_len, value_len;
	char cryptkey[33];
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &name, &name_len, &value, &value_len) == FAILURE) {
		return;
	}
	
	if (!SUHOSIN_G(cookie_encrypt)) {
return_plain:
		RETURN_STRINGL(value, value_len, 1);
	}
	
	if (SUHOSIN_G(cookie_plainlist)) {
		if (zend_hash_exists(SUHOSIN_G(cookie_plainlist), name, name_len+1)) {
			goto return_plain;
		}
	} else if (SUHOSIN_G(cookie_cryptlist)) {
		if (!zend_hash_exists(SUHOSIN_G(cookie_cryptlist), name, name_len+1)) {
			goto return_plain;
		}
	}
	
	suhosin_generate_key(SUHOSIN_G(cookie_cryptkey), SUHOSIN_G(cookie_cryptua), SUHOSIN_G(cookie_cryptdocroot), SUHOSIN_G(cookie_cryptraddr), (char *)&cryptkey TSRMLS_CC);
	value = suhosin_encrypt_string(value, value_len, name, name_len, (char *)&cryptkey TSRMLS_CC);
	
	RETVAL_STRING(value, 0);
}
/* }}} */

/* {{{ proto mixed suhosin_get_raw_cookies()
   Returns an array containing the raw cookie values */
static PHP_FUNCTION(suhosin_get_raw_cookies)
{
	char *var, *val, *res;
    zval *array_ptr = return_value;
    char *strtok_buf = NULL;
    int val_len;
    
	array_init(array_ptr);

    if (SUHOSIN_G(raw_cookie)) {
        res = estrdup(SUHOSIN_G(raw_cookie));
    } else {
        return;
    }

	var = php_strtok_r(res, ";", &strtok_buf);
	
	while (var) {
		val = strchr(var, '=');
		if (val) { /* have a value */
			*val++ = '\0';
			php_url_decode(var, strlen(var));
			val_len = php_url_decode(val, strlen(val));
			suhosin_register_cookie_variable_safe(var, val, val_len, array_ptr TSRMLS_CC);
		} else {
			php_url_decode(var, strlen(var));
			val_len = 0;
			val = "";
			suhosin_register_cookie_variable_safe(var, "", 0, array_ptr TSRMLS_CC);
		}
		var = php_strtok_r(NULL, ";", &strtok_buf);
	}
	
    efree(res);
}
/* }}} */



/* {{{ suhosin_functions[]
 */
zend_function_entry suhosin_functions[] = {
	PHP_NAMED_FE(suhosin_encrypt_cookie, PHP_FN(suhosin_encrypt_cookie), NULL)
	PHP_NAMED_FE(suhosin_get_raw_cookies, PHP_FN(suhosin_get_raw_cookies), NULL)
	{NULL, NULL, NULL}	/* Must be the last line in suhosin_functions[] */
};
/* }}} */

/* {{{ suhosin_module_entry
 */
zend_module_entry suhosin_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"suhosin",
	suhosin_functions,
	PHP_MINIT(suhosin),
	PHP_MSHUTDOWN(suhosin),
	PHP_RINIT(suhosin),
	PHP_RSHUTDOWN(suhosin),
	PHP_MINFO(suhosin),
#if ZEND_MODULE_API_NO >= 20010901
	SUHOSIN_EXT_VERSION, /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_SUHOSIN
ZEND_GET_MODULE(suhosin)
#endif

/* {{{ PHP_INI
 */
static zend_ini_entry shared_ini_entries[] = {
	ZEND_INI_ENTRY("suhosin.log.syslog",			NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_syslog)
	ZEND_INI_ENTRY("suhosin.log.syslog.facility",		NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_syslog_facility)
	ZEND_INI_ENTRY("suhosin.log.syslog.priority",		NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_syslog_priority)
	ZEND_INI_ENTRY("suhosin.log.sapi",				"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_sapi)
	ZEND_INI_ENTRY("suhosin.log.script",			"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_script)
	ZEND_INI_ENTRY("suhosin.log.script.name",			NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_scriptname)
	STD_ZEND_INI_BOOLEAN("suhosin.log.use-x-forwarded-for",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateLogBool, log_use_x_forwarded_for,	zend_suhosin_globals,	suhosin_globals)
	ZEND_INI_ENTRY("suhosin.log.phpscript",			"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_phpscript)
	STD_ZEND_INI_ENTRY("suhosin.log.phpscript.name",			NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateLogString, log_phpscriptname, zend_suhosin_globals, suhosin_globals)
	ZEND_INI_ENTRY("suhosin.log.file",			"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSuhosin_log_file)
	STD_ZEND_INI_ENTRY("suhosin.log.file.name",		NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateLogString, log_filename, zend_suhosin_globals, suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.log.phpscript.is_safe",			"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateLogBool, log_phpscript_is_safe,	zend_suhosin_globals,	suhosin_globals)
ZEND_INI_END()
 
PHP_INI_BEGIN()
    ZEND_INI_ENTRY("suhosin.perdir",		"0",		ZEND_INI_SYSTEM,	OnUpdateSuhosin_perdir)
	STD_ZEND_INI_ENTRY("suhosin.executor.include.max_traversal",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateExecLong, executor_include_max_traversal,	zend_suhosin_globals,	suhosin_globals)
	ZEND_INI_ENTRY("suhosin.executor.include.whitelist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_include_whitelist)
	ZEND_INI_ENTRY("suhosin.executor.include.blacklist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_include_blacklist)
	STD_ZEND_INI_BOOLEAN("suhosin.executor.include.allow_writable_files",	"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateExecBool, executor_include_allow_writable_files,	zend_suhosin_globals,	suhosin_globals)
        ZEND_INI_ENTRY("suhosin.executor.eval.whitelist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_eval_whitelist)
	ZEND_INI_ENTRY("suhosin.executor.eval.blacklist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_eval_blacklist)
	ZEND_INI_ENTRY("suhosin.executor.func.whitelist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_func_whitelist)
	ZEND_INI_ENTRY("suhosin.executor.func.blacklist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_func_blacklist)
	STD_ZEND_INI_BOOLEAN("suhosin.executor.disable_eval",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateExecBool, executor_disable_eval,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.executor.disable_emodifier",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateExecBool, executor_disable_emod,	zend_suhosin_globals,	suhosin_globals)

	STD_ZEND_INI_BOOLEAN("suhosin.executor.allow_symlink",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateExecBool, executor_allow_symlink,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_ENTRY("suhosin.executor.max_depth",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateExecLong, max_execution_depth,	zend_suhosin_globals,	suhosin_globals)

	
	STD_ZEND_INI_BOOLEAN("suhosin.multiheader",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateMiscBool, allow_multiheader,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_ENTRY("suhosin.mail.protect",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateMiscLong, mailprotect,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_ENTRY("suhosin.memory_limit",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateMiscLong, memory_limit,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.simulation",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateMiscBool, simulation,	zend_suhosin_globals,	suhosin_globals)
      STD_PHP_INI_ENTRY("suhosin.filter.action", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscString, filter_action, zend_suhosin_globals, suhosin_globals)

	STD_ZEND_INI_BOOLEAN("suhosin.protectkey",		"1",		ZEND_INI_SYSTEM,	OnUpdateBool, protectkey,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.coredump",		"0",		ZEND_INI_SYSTEM,	OnUpdateBool, coredump,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.stealth",		"1",		ZEND_INI_SYSTEM,	OnUpdateBool, stealth,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.apc_bug_workaround",		"0",		ZEND_INI_SYSTEM,	OnUpdateBool, apc_bug_workaround,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.disable.display_errors",		"0",		ZEND_INI_SYSTEM,	OnUpdateBool, disable_display_errors,	zend_suhosin_globals,	suhosin_globals)
	
	

        STD_PHP_INI_ENTRY("suhosin.request.max_vars", "1000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_request_variables, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_varname_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_varname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_value_length", "1000000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_value_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_array_depth, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_totalname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_array_index_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestBool, disallow_nul, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.request.disallow_ws", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestBool, disallow_ws, zend_suhosin_globals, suhosin_globals)
    
        STD_PHP_INI_ENTRY("suhosin.cookie.max_vars", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_vars, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_name_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_totalname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_value_length", "10000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_value_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_array_depth, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_array_index_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieBool, disallow_cookie_nul, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.cookie.disallow_ws", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieBool, disallow_cookie_ws, zend_suhosin_globals, suhosin_globals)

        STD_PHP_INI_ENTRY("suhosin.get.max_vars", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_vars, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_name_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_totalname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_value_length", "512", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_value_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_array_depth, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_array_index_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetBool, disallow_get_nul, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.get.disallow_ws", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetBool, disallow_get_ws, zend_suhosin_globals, suhosin_globals)

        STD_PHP_INI_ENTRY("suhosin.post.max_vars", "1000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_vars, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_name_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_totalname_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_value_length", "1000000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_value_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_array_depth, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_array_index_length, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostBool, disallow_post_nul, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.post.disallow_ws", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostBool, disallow_post_ws, zend_suhosin_globals, suhosin_globals)

        STD_PHP_INI_ENTRY("suhosin.upload.max_uploads", "25", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadLong, upload_limit, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.upload.disallow_elf", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadBool, upload_disallow_elf, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.upload.disallow_binary", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadBool, upload_disallow_binary, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.upload.remove_binary", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadBool, upload_remove_binary, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.upload.verification_script", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadString, upload_verification_script, zend_suhosin_globals, suhosin_globals)


        STD_ZEND_INI_BOOLEAN("suhosin.sql.bailout_on_error",	"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateSQLBool, sql_bailout_on_error,	zend_suhosin_globals,	suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.sql.user_prefix", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLString, sql_user_prefix, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.sql.user_postfix", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLString, sql_user_postfix, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.sql.comment", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLLong, sql_comment, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.sql.opencomment", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLLong, sql_opencomment, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.sql.multiselect", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLLong, sql_mselect, zend_suhosin_globals, suhosin_globals)
        STD_PHP_INI_ENTRY("suhosin.sql.union", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLLong, sql_union, zend_suhosin_globals, suhosin_globals)
    
	STD_ZEND_INI_BOOLEAN("suhosin.session.encrypt",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, session_encrypt,	zend_suhosin_globals,	suhosin_globals)
	STD_PHP_INI_ENTRY("suhosin.session.cryptkey", "", PHP_INI_ALL, OnUpdateString, session_cryptkey, zend_suhosin_globals, suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.session.cryptua",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, session_cryptua,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.session.cryptdocroot",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, session_cryptdocroot,	zend_suhosin_globals,	suhosin_globals)
	STD_PHP_INI_ENTRY("suhosin.session.cryptraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, session_cryptraddr, zend_suhosin_globals, suhosin_globals)	
	STD_PHP_INI_ENTRY("suhosin.session.checkraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, session_checkraddr, zend_suhosin_globals, suhosin_globals)	
	STD_PHP_INI_ENTRY("suhosin.session.max_id_length", "128", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, session_max_id_length, zend_suhosin_globals, suhosin_globals)
	

	STD_ZEND_INI_BOOLEAN("suhosin.cookie.encrypt",		"0",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, cookie_encrypt,	zend_suhosin_globals,	suhosin_globals)
	STD_PHP_INI_ENTRY("suhosin.cookie.cryptkey", "", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateString, cookie_cryptkey, zend_suhosin_globals, suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.cookie.cryptua",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, cookie_cryptua,	zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.cookie.cryptdocroot",		"1",		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdateBool, cookie_cryptdocroot,	zend_suhosin_globals,	suhosin_globals)
	STD_PHP_INI_ENTRY("suhosin.cookie.cryptraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, cookie_cryptraddr, zend_suhosin_globals, suhosin_globals)	
	STD_PHP_INI_ENTRY("suhosin.cookie.checkraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, cookie_checkraddr, zend_suhosin_globals, suhosin_globals)	
	ZEND_INI_ENTRY("suhosin.cookie.cryptlist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_cookie_cryptlist)
	ZEND_INI_ENTRY("suhosin.cookie.plainlist",	NULL,		ZEND_INI_PERDIR|ZEND_INI_SYSTEM,	OnUpdate_cookie_plainlist)


	STD_ZEND_INI_BOOLEAN("suhosin.server.encode", "1", ZEND_INI_SYSTEM, OnUpdateBool, server_encode,zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.server.strip", "1", ZEND_INI_SYSTEM, OnUpdateBool, server_strip,zend_suhosin_globals,	suhosin_globals)

	STD_ZEND_INI_BOOLEAN("suhosin.srand.ignore", "1", ZEND_INI_SYSTEM|ZEND_INI_PERDIR, OnUpdateMiscBool, srand_ignore,zend_suhosin_globals,	suhosin_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.mt_srand.ignore", "1", ZEND_INI_SYSTEM|ZEND_INI_PERDIR, OnUpdateMiscBool, mt_srand_ignore,zend_suhosin_globals,	suhosin_globals)

PHP_INI_END()
/* }}} */


/* {{{ php_suhosin_init_globals
 */
void suhosin_bailout(TSRMLS_D)
{
	if (!SUHOSIN_G(simulation)) {
		zend_bailout();
	}
}
/* }}} */

/* {{{ php_suhosin_init_globals
 */
STATIC void php_suhosin_init_globals(zend_suhosin_globals *suhosin_globals)
{
	memset(suhosin_globals, 0, sizeof(zend_suhosin_globals));
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(suhosin)
{
	SDEBUG("(MINIT)");
	ZEND_INIT_MODULE_GLOBALS(suhosin, php_suhosin_init_globals, NULL);

	/* only register constants if they have not previously been registered by a possible patched PHP */
	
	if (zend_hash_exists(EG(zend_constants), "S_MEMORY", sizeof("S_MEMORY"))==0) {
		REGISTER_MAIN_LONG_CONSTANT("S_MEMORY", S_MEMORY, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_VARS", S_VARS, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_FILES", S_FILES, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_INCLUDE", S_INCLUDE, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_SQL", S_SQL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_EXECUTOR", S_EXECUTOR, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_MAIL", S_MAIL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_SESSION", S_SESSION, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_MISC", S_MISC, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_INTERNAL", S_INTERNAL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_ALL", S_ALL, CONST_PERSISTENT | CONST_CS);
	}
	
	/* check if shared ini directives are already known (maybe a patched PHP) */
	if (zend_hash_exists(EG(ini_directives), "suhosin.log.syslog", sizeof("suhosin.log.syslog"))) {
	
		/* and update them */
		zend_ini_entry *p = (zend_ini_entry *)&shared_ini_entries;
		
		while (p->name) {
		
			zend_ini_entry *i;
			
			if (zend_hash_find(EG(ini_directives), p->name, p->name_length, (void **) &i)==FAILURE) {
				/* continue registering them */
				zend_register_ini_entries(p, module_number TSRMLS_CC);
				break;
			}
			
			SDEBUG("updating ini %s=%s", i->name, i->value);
			
#ifdef ZEND_ENGINE_2
			i->modifiable = p->modifiable;
#else
			i->modifyable = p->modifyable;
#endif
			i->module_number = module_number;
			i->on_modify = p->on_modify;
			i->mh_arg1 = p->mh_arg1;
			i->mh_arg2 = p->mh_arg2;
			i->mh_arg3 = p->mh_arg3;
			i->on_modify(i, i->value, i->value_length, i->mh_arg1, i->mh_arg2, i->mh_arg3, ZEND_INI_STAGE_STARTUP TSRMLS_CC);
			p++;
		}
	} else {
	
		/* not registered yet, then simply use the API */
		zend_register_ini_entries((zend_ini_entry *)&shared_ini_entries, module_number TSRMLS_CC);
		
	}

	/* and register the rest of the ini entries */
	REGISTER_INI_ENTRIES();
	
	/* Force display_errors=off */
	if (SUHOSIN_G(disable_display_errors)) {
		zend_ini_entry *i;
		if (zend_hash_find(EG(ini_directives), "display_errors", sizeof("display_errors"), (void **) &i) == SUCCESS) {
			if (i->on_modify) {
				i->on_modify(i, "0", sizeof("0"), i->mh_arg1, i->mh_arg2, i->mh_arg3, ZEND_INI_STAGE_STARTUP TSRMLS_CC);
				i->on_modify = NULL;
			}
		}
	}
	
	/* Load invisible to other Zend Extensions */
	if (zend_llist_count(&zend_extensions)==0 || SUHOSIN_G(stealth)==0) {
		zend_extension extension;
		extension = suhosin_zend_extension_entry;
		extension.handle = NULL;
		zend_llist_add_element(&zend_extensions, &extension);
        ze = NULL;
	} else {
		ze = (zend_extension *)zend_llist_get_last_ex(&zend_extensions, &lp);
		old_startup = ze->startup;
		ze->startup = suhosin_startup_wrapper;
	}

	/* now hook a bunch of stuff */
	suhosin_hook_memory_limit();
	suhosin_hook_crypt();
	suhosin_hook_sha256();
	suhosin_hook_ex_imp();

	/* register the logo for phpinfo */
	php_register_info_logo(SUHOSIN_LOGO_GUID, "image/jpeg", suhosin_logo, sizeof(suhosin_logo));

#if PHP_MAJOR_VERSION > 5 || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 1)
	/* perform LFS check */
/*	time_t check = sapi_get_request_time(TSRMLS_C);
	if (SG(global_request_time) != check) {
	    zend_error(E_ERROR, "It seems that PHP and Suhosin were compiled with different binary layouts. "
	    "This will cause problems like POST not working. Please tell your distributor to fix this.");
	}*/
#endif
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(suhosin)
{
	SDEBUG("(MSHUTDOWN)");
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(suhosin)
{
	SDEBUG("(RINIT)");
	SUHOSIN_G(in_code_type) = SUHOSIN_NORMAL;
	SUHOSIN_G(execution_depth) = 0;

	return SUCCESS;
}
/* }}} */


/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(suhosin)
{
	SDEBUG("(RSHUTDOWN)");
	
	/* We need to clear the input filtering 
	   variables in the request shutdown
	   because input filtering is done before 
	   RINIT */
	   
	SUHOSIN_G(cur_request_variables) = 0;
	SUHOSIN_G(cur_cookie_vars) = 0;
	SUHOSIN_G(cur_get_vars) = 0;
	SUHOSIN_G(cur_post_vars) = 0;
	SUHOSIN_G(num_uploads) = 0;

        SUHOSIN_G(no_more_variables) = 0;
        SUHOSIN_G(no_more_get_variables) = 0;
        SUHOSIN_G(no_more_post_variables) = 0;
        SUHOSIN_G(no_more_cookie_variables) = 0;
        SUHOSIN_G(no_more_uploads) = 0;
	
	SUHOSIN_G(abort_request) = 0;
	
	if (SUHOSIN_G(decrypted_cookie)) {
		efree(SUHOSIN_G(decrypted_cookie));
		SUHOSIN_G(decrypted_cookie)=NULL;
	}
    if (SUHOSIN_G(raw_cookie)) {
		efree(SUHOSIN_G(raw_cookie));
		SUHOSIN_G(raw_cookie)=NULL;
	}
	
	return SUCCESS;
}
/* }}} */

/* {{{ suhosin_ini_displayer(zend_ini_entry *ini_entry, int type)
 */
static void suhosin_ini_displayer(zend_ini_entry *ini_entry, int type)
{
    TSRMLS_FETCH();

    PHPWRITE("[ protected ]", strlen("[ protected ]"));
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(suhosin)
{
	php_info_print_box_start(0);
	if (!sapi_module.phpinfo_as_text) {
		if (PG(expose_php)) {
			PUTS("<a href=\"http://www.suhosin.org/\"><img border=\"0\" src=\"");
			if (SG(request_info).request_uri) {
				char *elem_esc = php_info_html_esc(SG(request_info).request_uri TSRMLS_CC);
				PUTS(elem_esc);
				efree(elem_esc);
			}
			PUTS("?="SUHOSIN_LOGO_GUID"\" alt=\"Suhosin logo\" /></a>\n");
		} else do {
			char *enc_logo;
			int ret;
			zval **agent_name;
			
#ifdef ZEND_ENGINE_2
			zend_is_auto_global("_SERVER", sizeof("_SERVER")-1 TSRMLS_CC);
#endif
			if (!PG(http_globals)[TRACK_VARS_SERVER] || 
			    zend_hash_find(PG(http_globals)[TRACK_VARS_SERVER]->value.ht, "HTTP_USER_AGENT", sizeof("HTTP_USER_AGENT"), (void **) &agent_name)==FAILURE) {
			    break;
			}
			if (Z_TYPE_PP(agent_name) != IS_STRING) {
			    break;
			}
			if (strstr(Z_STRVAL_PP(agent_name), "Gecko") == NULL && strstr(Z_STRVAL_PP(agent_name), "Opera") == NULL) {
			    break;
			}
			PUTS("<a href=\"http://www.suhosin.org/\"><img border=\"0\" src=\"data:image/jpeg;base64,");
			enc_logo=(char *)php_base64_encode(suhosin_logo, sizeof(suhosin_logo), &ret);
			if (enc_logo) {
				PUTS(enc_logo);
				efree(enc_logo);
			}
			PUTS("\" alt=\"Suhosin logo\" /></a>\n");
		} while(0);
	}
	PUTS("This server is protected with the Suhosin Extension " SUHOSIN_EXT_VERSION);
	PUTS(!sapi_module.phpinfo_as_text?"<br /><br />":"\n\n");
	if (sapi_module.phpinfo_as_text) {
		PUTS("Copyright (c) 2006-2007 Hardened-PHP Project\n");
		PUTS("Copyright (c) 2007-2010 SektionEins GmbH\n");
	} else {
		PUTS("Copyright (c) 2006-2007 <a href=\"http://www.hardened-php.net/\">Hardened-PHP Project</a><br />\n");
		PUTS("Copyright (c) 2007-2010 <a href=\"http://www.sektioneins.de/\">SektionEins GmbH</a>\n");
	}
	php_info_print_box_end();

    if (SUHOSIN_G(protectkey)) {
        zend_ini_entry *i;
		
		if (zend_hash_find(EG(ini_directives), "suhosin.cookie.cryptkey", sizeof("suhosin.cookie.cryptkey"), (void **) &i)==SUCCESS) {
            i->displayer = suhosin_ini_displayer;
        }
		if (zend_hash_find(EG(ini_directives), "suhosin.session.cryptkey", sizeof("suhosin.session.cryptkey"), (void **) &i)==SUCCESS) {
            i->displayer = suhosin_ini_displayer;
        }
    }
    
	DISPLAY_INI_ENTRIES();

    if (SUHOSIN_G(protectkey)) {
        zend_ini_entry *i;
		
		if (zend_hash_find(EG(ini_directives), "suhosin.cookie.cryptkey", sizeof("suhosin.cookie.cryptkey"), (void **) &i)==SUCCESS) {
            i->displayer = NULL;
        }
		if (zend_hash_find(EG(ini_directives), "suhosin.session.cryptkey", sizeof("suhosin.session.cryptkey"), (void **) &i)==SUCCESS) {
            i->displayer = NULL;
        }
    }

}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
