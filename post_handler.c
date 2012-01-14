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
}

void suhosin_unhook_post_handlers()
{
	/* Restore to an empty destructor */
	SG(known_post_content_types).pDestructor = NULL;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */


