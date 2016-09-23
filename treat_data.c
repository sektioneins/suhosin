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
  $Id: treat_data.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_suhosin.h"
#include "SAPI.h"
#include "php_variables.h"
#include "ext/standard/url.h"

SAPI_TREAT_DATA_FUNC(suhosin_treat_data)
{
	char *res = NULL, *var, *val, *separator = NULL;
	const char *c_var;
	zval *array_ptr;
	int free_buffer = 0;
	char *strtok_buf = NULL;

	long count = 0;

	/* Mark that we were not yet called */
	SUHOSIN_G(already_scanned) = 0;

	switch (arg) {
		case PARSE_POST:
		case PARSE_GET:
		case PARSE_COOKIE:
			ALLOC_ZVAL(array_ptr);
			array_init(array_ptr);
			INIT_PZVAL(array_ptr);
			switch (arg) {
				case PARSE_POST:
					if (PG(http_globals)[TRACK_VARS_POST]) {
						zval_ptr_dtor(&PG(http_globals)[TRACK_VARS_POST]);
					}
					PG(http_globals)[TRACK_VARS_POST] = array_ptr;

					if (SUHOSIN_G(max_request_variables) && (SUHOSIN_G(max_post_vars) == 0 ||
						SUHOSIN_G(max_request_variables) <= SUHOSIN_G(max_post_vars))) {
						SUHOSIN_G(max_post_vars) = SUHOSIN_G(max_request_variables);
					}
					break;
				case PARSE_GET:
					if (PG(http_globals)[TRACK_VARS_GET]) {
						zval_ptr_dtor(&PG(http_globals)[TRACK_VARS_GET]);
					}
					PG(http_globals)[TRACK_VARS_GET] = array_ptr;
					if (SUHOSIN_G(max_request_variables) && (SUHOSIN_G(max_get_vars) == 0 ||
						SUHOSIN_G(max_request_variables) <= SUHOSIN_G(max_get_vars))) {
						SUHOSIN_G(max_get_vars) = SUHOSIN_G(max_request_variables);
					}
					break;
				case PARSE_COOKIE:
					if (PG(http_globals)[TRACK_VARS_COOKIE]) {
						zval_ptr_dtor(&PG(http_globals)[TRACK_VARS_COOKIE]);
					}
					PG(http_globals)[TRACK_VARS_COOKIE] = array_ptr;
					if (SUHOSIN_G(max_request_variables) && (SUHOSIN_G(max_cookie_vars) == 0 ||
						SUHOSIN_G(max_request_variables) <= SUHOSIN_G(max_cookie_vars))) {
						SUHOSIN_G(max_cookie_vars) = SUHOSIN_G(max_request_variables);
					}
					break;
			}
			break;
		default:
			array_ptr = destArray;
			break;
	}

	if (arg == PARSE_POST) {
		sapi_handle_post(array_ptr TSRMLS_CC);
		return;
	}

	if (arg == PARSE_GET) {		/* GET data */
		c_var = SG(request_info).query_string;
		if (c_var && *c_var) {
			res = (char *) estrdup(c_var);
			free_buffer = 1;
		} else {
			free_buffer = 0;
		}
	} else if (arg == PARSE_COOKIE) {		/* Cookie data */
		c_var = SG(request_info).cookie_data;
		if (c_var && *c_var) {
			if (SUHOSIN_G(cookie_encrypt)) {
				res = (char *) estrdup(suhosin_cookie_decryptor(TSRMLS_C));
			} else {
				res = (char *) estrdup(c_var);
			}
			free_buffer = 1;
		} else {
			free_buffer = 0;
		}
	} else if (arg == PARSE_STRING) {		/* String data */
		res = str;
		free_buffer = 1;
	}

	if (!res) {
		return;
	}

	switch (arg) {
		case PARSE_GET:
		case PARSE_STRING:
			separator = (char *) estrdup(PG(arg_separator).input);
			break;
		case PARSE_COOKIE:
			separator = ";\0";
			break;
	}

	var = php_strtok_r(res, separator, &strtok_buf);

	while (var) {

		if (arg == PARSE_COOKIE) {
			/* Remove leading spaces from cookie names, needed for multi-cookie header where ; can be followed by a space */
			while (isspace(*var)) {
				var++;
			}
		}
		val = strchr(var, '=');

		if (++count > PG(max_input_vars)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Input variables exceeded %ld. To increase the limit change max_input_vars in php.ini.", PG(max_input_vars));
			break;
		}

		if (val) { /* have a value */
			int val_len;
			unsigned int new_val_len;

			*val++ = '\0';
			php_url_decode(var, strlen(var));
			val_len = php_url_decode(val, strlen(val));
			val = estrndup(val, val_len);
			if (suhosin_input_filter(arg, var, &val, val_len, &new_val_len TSRMLS_CC)) {
				if (sapi_module.input_filter(arg, var, &val, new_val_len, &new_val_len TSRMLS_CC)) {
					php_register_variable_safe(var, val, new_val_len, array_ptr TSRMLS_CC);
				}
			} else {
				SUHOSIN_G(abort_request) = 1;
			}
			efree(val);
		} else {
			int val_len;
			unsigned int new_val_len;

			php_url_decode(var, strlen(var));
			val_len = 0;
			val = estrndup("", val_len);
			if (suhosin_input_filter(arg, var, &val, val_len, &new_val_len TSRMLS_CC)) {
				if (sapi_module.input_filter(arg, var, &val, new_val_len, &new_val_len TSRMLS_CC)) {
					php_register_variable_safe(var, val, new_val_len, array_ptr TSRMLS_CC);
				}
			} else {
				SUHOSIN_G(abort_request) = 1;
			}
			efree(val);
		}
		var = php_strtok_r(NULL, separator, &strtok_buf);
	}

	if (arg != PARSE_COOKIE) {
		efree(separator);
	}

	if (free_buffer) {
		efree(res);
	}
}


void suhosin_hook_treat_data()
{
	TSRMLS_FETCH();

	sapi_register_treat_data(suhosin_treat_data TSRMLS_CC);

	if (old_input_filter == NULL) {
		old_input_filter = sapi_module.input_filter;
	}
	sapi_module.input_filter = suhosin_input_filter_wrapper;
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
