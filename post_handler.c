/*
  +----------------------------------------------------------------------+
  | Suhosin Version 1                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2007 The Hardened-PHP Project                     |
  | Copyright (c) 2007-2012 SektionEins GmbH                             |
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
  $Id: post_handler.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $ 
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_suhosin.h"
#include "SAPI.h"
#include "php_variables.h"
#include "php_content_types.h"
#include "suhosin_rfc1867.h"
#include "ext/standard/url.h"

SAPI_POST_HANDLER_FUNC(suhosin_rfc1867_post_handler);


SAPI_POST_HANDLER_FUNC(suhosin_std_post_handler)
{
    char *var, *val, *e, *s, *p;
    zval *array_ptr = (zval *) arg;

    if (SG(request_info).post_data==NULL) {
        return;
    }	

    s = SG(request_info).post_data;
    e = s + SG(request_info).post_data_length;

    while (s < e && (p = memchr(s, '&', (e - s)))) {
last_value:
        if ((val = memchr(s, '=', (p - s)))) { /* have a value */
            unsigned int val_len, new_val_len;
            var = s;

            php_url_decode(var, (val - s));
            val++;
            val_len = php_url_decode(val, (p - val));
            val = estrndup(val, val_len);
            if (suhosin_input_filter(PARSE_POST, var, &val, val_len, &new_val_len TSRMLS_CC)) {
#ifdef ZEND_ENGINE_2
                if (sapi_module.input_filter(PARSE_POST, var, &val, new_val_len, &new_val_len TSRMLS_CC)) {
#endif
                    php_register_variable_safe(var, val, new_val_len, array_ptr TSRMLS_CC);
#ifdef ZEND_ENGINE_2
                }
#endif
            } else {
                SUHOSIN_G(abort_request)=1;
            }
            efree(val);
        }
        s = p + 1;
    }
    if (s < e) {
        p = e;
        goto last_value;
    }
}

static void suhosin_post_handler_modification(sapi_post_entry *spe)
{
	char *content_type = estrndup(spe->content_type, spe->content_type_len);
	suhosin_log(S_VARS, "some extension replaces the POST handler for %s - Suhosin's protection will be incomplete", content_type);
	efree(content_type);
}

static int (*old_OnUpdate_mbstring_encoding_translation)(zend_ini_entry *entry, char *new_value, uint new_value_length, void *mh_arg1, void *mh_arg2, void *mh_arg3, int stage TSRMLS_DC) = NULL;

/* {{{ static PHP_INI_MH(suhosin_OnUpdate_mbstring_encoding_translation) */
static PHP_INI_MH(suhosin_OnUpdate_mbstring_encoding_translation)
{
	zend_bool *p;
#ifndef ZTS
	char *base = (char *) mh_arg2;
#else
	char *base;

	base = (char *) ts_resource(*((int *) mh_arg2));
#endif

	p = (zend_bool *) (base+(size_t) mh_arg1);

	if (new_value_length == 2 && strcasecmp("on", new_value) == 0) {
			*p = (zend_bool) 1;
	}
	else if (new_value_length == 3 && strcasecmp("yes", new_value) == 0) {
		*p = (zend_bool) 1;
	}
	else if (new_value_length == 4 && strcasecmp("true", new_value) == 0) {
		*p = (zend_bool) 1;
	}
	else {
		*p = (zend_bool) atoi(new_value);
	}
	if (*p) {
		suhosin_log(S_VARS, "Dynamic configuration (maybe a .htaccess file) tried to activate mbstring.encoding_translation which is incompatible with suhosin");
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_post_entries[]
 */
static sapi_post_entry suhosin_post_entries[] = {
	{ DEFAULT_POST_CONTENT_TYPE, sizeof(DEFAULT_POST_CONTENT_TYPE)-1, sapi_read_standard_form_data,	suhosin_std_post_handler },
	{ MULTIPART_CONTENT_TYPE,    sizeof(MULTIPART_CONTENT_TYPE)-1,    NULL,                         suhosin_rfc1867_post_handler },
	{ NULL, 0, NULL, NULL }
};
/* }}} */

void suhosin_hook_post_handlers(TSRMLS_D)
{
	HashTable tempht;
	zend_ini_entry *ini_entry;
	
#if PHP_MAJOR_VERSION > 5 || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 0)
	sapi_unregister_post_entry(&suhosin_post_entries[0] TSRMLS_CC);
	sapi_unregister_post_entry(&suhosin_post_entries[1] TSRMLS_CC);
	sapi_register_post_entries(suhosin_post_entries TSRMLS_CC);
#else
	sapi_unregister_post_entry(&suhosin_post_entries[0]);
	sapi_unregister_post_entry(&suhosin_post_entries[1]);
	sapi_register_post_entries(suhosin_post_entries);
#endif
	/* we want to get notified if another extension deregisters the suhosin post handlers */

	/* we need to tell suhosin patch that there is a new valid destructor */
	/* therefore we have create HashTable that has this destructor */
	zend_hash_init(&tempht, 0, NULL, suhosin_post_handler_modification, 0);
	zend_hash_destroy(&tempht);
	/* And now we can overwrite the destructor for post entries */
	SG(known_post_content_types).pDestructor = suhosin_post_handler_modification;
	
	/* we have to stop mbstring from replacing our post handler */
	if (zend_hash_find(EG(ini_directives), "mbstring.encoding_translation", sizeof("mbstring.encoding_translation"), (void **) &ini_entry) == FAILURE) {
		return;
	}
	/* replace OnUpdate_mbstring_encoding_translation handler */
	old_OnUpdate_mbstring_encoding_translation = ini_entry->on_modify;
	ini_entry->on_modify = suhosin_OnUpdate_mbstring_encoding_translation;
}

void suhosin_unhook_post_handlers()
{
	zend_ini_entry *ini_entry;

	/* Restore to an empty destructor */
	SG(known_post_content_types).pDestructor = NULL;

	/* Now restore the ini entry handler */
	if (zend_hash_find(EG(ini_directives), "mbstring.encoding_translation", sizeof("mbstring.encoding_translation"), (void **) &ini_entry) == FAILURE) {
		return;
	}
	/* replace OnUpdate_mbstring_encoding_translation handler */
	ini_entry->on_modify = old_OnUpdate_mbstring_encoding_translation;
	old_OnUpdate_mbstring_encoding_translation = NULL;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */


