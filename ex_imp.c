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
/*
  $Id: ex_imp.c,v 1.2 2008-01-04 11:23:47 sesser Exp $ 
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_suhosin.h"
#include "ext/standard/php_smart_str.h"
#include "ext/standard/php_var.h"


#define EXTR_OVERWRITE			0
#define EXTR_SKIP				1
#define EXTR_PREFIX_SAME		2
#define	EXTR_PREFIX_ALL			3
#define	EXTR_PREFIX_INVALID		4
#define	EXTR_PREFIX_IF_EXISTS	5
#define	EXTR_IF_EXISTS			6

#define EXTR_REFS				0x100


static int php_valid_var_name(char *var_name, int len) /* {{{ */
{
	int i, ch;
	
	if (!var_name)
		return 0;

	/* These are allowed as first char: [a-zA-Z_\x7f-\xff] */
	ch = (int)((unsigned char *)var_name)[0];
	if (var_name[0] != '_' &&
		(ch < 65  /* A    */ || /* Z    */ ch > 90)  &&
		(ch < 97  /* a    */ || /* z    */ ch > 122) &&
		(ch < 127 /* 0x7f */ || /* 0xff */ ch > 255)
	) {
		return 0;
	}

	/* And these as the rest: [a-zA-Z0-9_\x7f-\xff] */
	if (len > 1) {
		for (i = 1; i < len; i++) {
			ch = (int)((unsigned char *)var_name)[i];
			if (var_name[i] != '_' &&
				(ch < 48  /* 0    */ || /* 9    */ ch > 57)  &&
				(ch < 65  /* A    */ || /* Z    */ ch > 90)  &&
				(ch < 97  /* a    */ || /* z    */ ch > 122) &&
				(ch < 127 /* 0x7f */ || /* 0xff */ ch > 255)
			) {	
				return 0;
			}
		}
	}

	if (var_name[0] == 'H') {
		if ((strcmp(var_name, "HTTP_GET_VARS")==0)||
		    (strcmp(var_name, "HTTP_POST_VARS")==0)||
		    (strcmp(var_name, "HTTP_POST_FILES")==0)||
		    (strcmp(var_name, "HTTP_ENV_VARS")==0)||
		    (strcmp(var_name, "HTTP_SERVER_VARS")==0)||
		    (strcmp(var_name, "HTTP_SESSION_VARS")==0)||
		    (strcmp(var_name, "HTTP_COOKIE_VARS")==0)||
		    (strcmp(var_name, "HTTP_RAW_POST_DATA")==0)) {
		    return 0;
		}
	} else if (var_name[0] == '_') {
		if ((strcmp(var_name, "_COOKIE")==0)||
		    (strcmp(var_name, "_ENV")==0)||
		    (strcmp(var_name, "_FILES")==0)||
		    (strcmp(var_name, "_GET")==0)||
		    (strcmp(var_name, "_POST")==0)||
		    (strcmp(var_name, "_REQUEST")==0)||
		    (strcmp(var_name, "_SESSION")==0)||
		    (strcmp(var_name, "_SERVER")==0)) {
		    return 0;
		}
	} else if (strcmp(var_name, "GLOBALS")==0) {
		return 0;
	}
	
	return 1;
}


/* {{{ proto int extract(array var_array [, int extract_type [, string prefix]])
   Imports variables into symbol table from an array */
PHP_FUNCTION(suhosin_extract)
{
#if PHP_VERSION_ID >= 50300	
	zval *var_array, *prefix = NULL;
	long extract_type = EXTR_OVERWRITE;
	zval **entry, *data;
	char *var_name;
	ulong num_key;
	uint var_name_len;
	int var_exists, key_type, count = 0;
	int extract_refs = 0;
	HashPosition pos;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a|lz/", &var_array, &extract_type, &prefix) == FAILURE) {
		return;
	}

	extract_refs = (extract_type & EXTR_REFS);
	extract_type &= 0xff;

	if (extract_type < EXTR_OVERWRITE || extract_type > EXTR_IF_EXISTS) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid extract type");
		return;
	}

	if (extract_type > EXTR_SKIP && extract_type <= EXTR_PREFIX_IF_EXISTS && ZEND_NUM_ARGS() < 3) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "specified extract type requires the prefix parameter");
		return;
	}

	if (prefix) {
		convert_to_string(prefix);
		if (Z_STRLEN_P(prefix) && !php_valid_var_name(Z_STRVAL_P(prefix), Z_STRLEN_P(prefix))) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "prefix is not a valid identifier");
			return;
		}
	}

	if (!EG(active_symbol_table)) {
		zend_rebuild_symbol_table(TSRMLS_C);
	}

	/* var_array is passed by ref for the needs of EXTR_REFS (needs to
	 * work on the original array to create refs to its members)
	 * simulate pass_by_value if EXTR_REFS is not used */
	if (!extract_refs) {
		SEPARATE_ARG_IF_REF(var_array);
	}

	zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(var_array), &pos);
	while (zend_hash_get_current_data_ex(Z_ARRVAL_P(var_array), (void **)&entry, &pos) == SUCCESS) {
		zval final_name;

		ZVAL_NULL(&final_name);

		key_type = zend_hash_get_current_key_ex(Z_ARRVAL_P(var_array), &var_name, &var_name_len, &num_key, 0, &pos);
		var_exists = 0;

		if (key_type == HASH_KEY_IS_STRING) {
			var_name_len--;
			var_exists = zend_hash_exists(EG(active_symbol_table), var_name, var_name_len + 1);
		} else if (key_type == HASH_KEY_IS_LONG && (extract_type == EXTR_PREFIX_ALL || extract_type == EXTR_PREFIX_INVALID)) {
			zval num;

			ZVAL_LONG(&num, num_key);
			convert_to_string(&num);
			php_prefix_varname(&final_name, prefix, Z_STRVAL(num), Z_STRLEN(num), 1 TSRMLS_CC);
			zval_dtor(&num);
		} else {
			zend_hash_move_forward_ex(Z_ARRVAL_P(var_array), &pos);
			continue;
		}

		switch (extract_type) {
			case EXTR_IF_EXISTS:
				if (!var_exists) break;
				/* break omitted intentionally */

			case EXTR_OVERWRITE:
				/* GLOBALS protection */
				if (var_exists && var_name_len == sizeof("GLOBALS") && !strcmp(var_name, "GLOBALS")) {
					break;
				}
				if (var_exists && var_name_len == sizeof("this")  && !strcmp(var_name, "this") && EG(scope) && EG(scope)->name_length != 0) {
					break;
				}
				ZVAL_STRINGL(&final_name, var_name, var_name_len, 1);
				break;

			case EXTR_PREFIX_IF_EXISTS:
				if (var_exists) {
					php_prefix_varname(&final_name, prefix, var_name, var_name_len, 1 TSRMLS_CC);
				}
				break;

			case EXTR_PREFIX_SAME:
				if (!var_exists && var_name_len != 0) {
					ZVAL_STRINGL(&final_name, var_name, var_name_len, 1);
				}
				/* break omitted intentionally */

			case EXTR_PREFIX_ALL:
				if (Z_TYPE(final_name) == IS_NULL && var_name_len != 0) {
					php_prefix_varname(&final_name, prefix, var_name, var_name_len, 1 TSRMLS_CC);
				}
				break;

			case EXTR_PREFIX_INVALID:
				if (Z_TYPE(final_name) == IS_NULL) {
					if (!php_valid_var_name(var_name, var_name_len)) {
						php_prefix_varname(&final_name, prefix, var_name, var_name_len, 1 TSRMLS_CC);
					} else {
						ZVAL_STRINGL(&final_name, var_name, var_name_len, 1);
					}
				}
				break;

			default:
				if (!var_exists) {
					ZVAL_STRINGL(&final_name, var_name, var_name_len, 1);
				}
				break;
		}

		if (Z_TYPE(final_name) != IS_NULL && php_valid_var_name(Z_STRVAL(final_name), Z_STRLEN(final_name))) {
			if (extract_refs) {
				zval **orig_var;

				SEPARATE_ZVAL_TO_MAKE_IS_REF(entry);
				zval_add_ref(entry);

				if (zend_hash_find(EG(active_symbol_table), Z_STRVAL(final_name), Z_STRLEN(final_name) + 1, (void **) &orig_var) == SUCCESS) {
					zval_ptr_dtor(orig_var);
					*orig_var = *entry;
				} else {
					zend_hash_update(EG(active_symbol_table), Z_STRVAL(final_name), Z_STRLEN(final_name) + 1, (void **) entry, sizeof(zval *), NULL);
				}
			} else {
				MAKE_STD_ZVAL(data);
				*data = **entry;
				zval_copy_ctor(data);

				ZEND_SET_SYMBOL_WITH_LENGTH(EG(active_symbol_table), Z_STRVAL(final_name), Z_STRLEN(final_name) + 1, data, 1, 0);
			}
			count++;
		}
		zval_dtor(&final_name);

		zend_hash_move_forward_ex(Z_ARRVAL_P(var_array), &pos);
	}

	if (!extract_refs) {
		zval_ptr_dtor(&var_array);
	}

	RETURN_LONG(count);
#else
	zval **var_array, *orig_var_array, **z_extract_type, **prefix;
	zval **entry, *data;
	char *var_name;
	smart_str final_name = {0};
	ulong num_key;
	uint var_name_len;
	int var_exists, extract_type, key_type, count = 0;
	int extract_refs = 0;
	HashPosition pos;

	switch (ZEND_NUM_ARGS()) {
		case 1:
			if (zend_get_parameters_ex(1, &var_array) == FAILURE) {
				WRONG_PARAM_COUNT;
			}
			extract_type = EXTR_OVERWRITE;
			break;

		case 2:
			if (zend_get_parameters_ex(2, &var_array, &z_extract_type) == FAILURE) {
				WRONG_PARAM_COUNT;
			}
			convert_to_long_ex(z_extract_type);
			extract_type = Z_LVAL_PP(z_extract_type);
			extract_refs = (extract_type & EXTR_REFS);
			extract_type &= 0xff;
			if (extract_type > EXTR_SKIP && extract_type <= EXTR_PREFIX_IF_EXISTS) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Prefix expected to be specified");
				return;
			}
			break;
			
		case 3:
			if (zend_get_parameters_ex(3, &var_array, &z_extract_type, &prefix) == FAILURE) {
				WRONG_PARAM_COUNT;
			}
			convert_to_long_ex(z_extract_type);
			extract_type = Z_LVAL_PP(z_extract_type);
			extract_refs = (extract_type & EXTR_REFS);
			extract_type &= 0xff;
			convert_to_string_ex(prefix);
			break;

		default:
			WRONG_PARAM_COUNT;
			break;
	}
	
	if (extract_type < EXTR_OVERWRITE || extract_type > EXTR_IF_EXISTS) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown extract type");
		return;
	}
	
	if (Z_TYPE_PP(var_array) != IS_ARRAY) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "First argument should be an array");
		return;
	}

	/* var_array is passed by ref for the needs of EXTR_REFS (needs to
	 * work on the original array to create refs to its members)
	 * simulate pass_by_value if EXTR_REFS is not used */
	if (!extract_refs) {
		orig_var_array = *var_array;
		SEPARATE_ARG_IF_REF((*var_array));
	}

	zend_hash_internal_pointer_reset_ex(Z_ARRVAL_PP(var_array), &pos);
	while (zend_hash_get_current_data_ex(Z_ARRVAL_PP(var_array), (void **)&entry, &pos) == SUCCESS) {
		key_type = zend_hash_get_current_key_ex(Z_ARRVAL_PP(var_array), &var_name, &var_name_len, &num_key, 0, &pos);
		var_exists = 0;

		if (key_type == HASH_KEY_IS_STRING) {
			var_name_len--;
			var_exists = zend_hash_exists(EG(active_symbol_table), var_name, var_name_len + 1);
		} else if (extract_type == EXTR_PREFIX_ALL || extract_type == EXTR_PREFIX_INVALID) {
			smart_str_appendl(&final_name, Z_STRVAL_PP(prefix), Z_STRLEN_PP(prefix));
			smart_str_appendc(&final_name, '_');
			smart_str_append_long(&final_name, num_key);
		} else {
			zend_hash_move_forward_ex(Z_ARRVAL_PP(var_array), &pos);
			continue;
		}
			
		switch (extract_type) {
			case EXTR_IF_EXISTS:
				if (!var_exists) break;
				/* break omitted intentionally */

			case EXTR_OVERWRITE:
				/* GLOBALS protection */
 				if (var_exists && var_name_len == sizeof("GLOBALS") && !strcmp(var_name, "GLOBALS")) {
 					break;
 				}
				if (var_exists && var_name_len == sizeof("this")  && !strcmp(var_name, "this") && EG(scope) && EG(scope)->name_length != 0) {
					break;
				}
				smart_str_appendl(&final_name, var_name, var_name_len);
				break;

			case EXTR_PREFIX_IF_EXISTS:
				if (var_exists) {
					smart_str_appendl(&final_name, Z_STRVAL_PP(prefix), Z_STRLEN_PP(prefix));
					smart_str_appendc(&final_name, '_');
					smart_str_appendl(&final_name, var_name, var_name_len);
				}
				break;

			case EXTR_PREFIX_SAME:
				if (!var_exists)
					smart_str_appendl(&final_name, var_name, var_name_len);
				/* break omitted intentionally */

			case EXTR_PREFIX_ALL:
				if (final_name.len == 0 && var_name_len != 0) {
					smart_str_appendl(&final_name, Z_STRVAL_PP(prefix), Z_STRLEN_PP(prefix));
					smart_str_appendc(&final_name, '_');
					smart_str_appendl(&final_name, var_name, var_name_len);
				}
				break;

			case EXTR_PREFIX_INVALID:
				if (final_name.len == 0) {
					if (!php_valid_var_name(var_name, var_name_len)) {
						smart_str_appendl(&final_name, Z_STRVAL_PP(prefix), Z_STRLEN_PP(prefix));
						smart_str_appendc(&final_name, '_');
						smart_str_appendl(&final_name, var_name, var_name_len);
					} else
						smart_str_appendl(&final_name, var_name, var_name_len);
				}
				break;

			default:
				if (!var_exists)
					smart_str_appendl(&final_name, var_name, var_name_len);
				break;
		}

		if (final_name.len) {
			smart_str_0(&final_name);
			if (php_valid_var_name(final_name.c, final_name.len)) {
				if (extract_refs) {
					zval **orig_var;

					SEPARATE_ZVAL_TO_MAKE_IS_REF(entry);
					zval_add_ref(entry);

					if (zend_hash_find(EG(active_symbol_table), final_name.c, final_name.len+1, (void **) &orig_var) == SUCCESS) {
						zval_ptr_dtor(orig_var);
						*orig_var = *entry;
					} else {
						zend_hash_update(EG(active_symbol_table), final_name.c, final_name.len+1, (void **) entry, sizeof(zval *), NULL);
					}
				} else {
					MAKE_STD_ZVAL(data);
					*data = **entry;
					zval_copy_ctor(data);

					ZEND_SET_SYMBOL_WITH_LENGTH(EG(active_symbol_table), final_name.c, final_name.len+1, data, 1, 0);
				}

				count++;
			}
			final_name.len = 0;
		}

		zend_hash_move_forward_ex(Z_ARRVAL_PP(var_array), &pos);
	}

	if (!extract_refs) {
		zval_ptr_dtor(var_array);
		*var_array = orig_var_array;
	}
	smart_str_free(&final_name);

	RETURN_LONG(count);
#endif	
}
/* }}} */


#if PHP_VERSION_ID >= 50300
static int copy_request_variable(void *pDest TSRMLS_DC, int num_args, va_list args, zend_hash_key *hash_key)
{
	zval *prefix, new_key;
	int prefix_len;
	zval **var = (zval **) pDest;

	if (num_args != 1) {
		return 0;
	}

	prefix = va_arg(args, zval *);
	prefix_len = Z_STRLEN_P(prefix);

	if (!prefix_len && !hash_key->nKeyLength) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Numeric key detected - possible security hazard");
		return 0;
	}

	if (hash_key->nKeyLength) {
		php_prefix_varname(&new_key, prefix, hash_key->arKey, hash_key->nKeyLength - 1, 0 TSRMLS_CC);
	} else {
		zval num;

		ZVAL_LONG(&num, hash_key->h);
		convert_to_string(&num);
		php_prefix_varname(&new_key, prefix, Z_STRVAL(num), Z_STRLEN(num), 0 TSRMLS_CC);
		zval_dtor(&num);
	}

	if (php_varname_check(Z_STRVAL(new_key), Z_STRLEN(new_key), 0 TSRMLS_CC) == FAILURE) {
		zval_dtor(&new_key);
		return 0;
	}

	if (Z_STRVAL(new_key)[0] == 'H') {
		if ((strcmp(Z_STRVAL(new_key), "HTTP_GET_VARS")==0)||
		    (strcmp(Z_STRVAL(new_key), "HTTP_POST_VARS")==0)||
		    (strcmp(Z_STRVAL(new_key), "HTTP_POST_FILES")==0)||
		    (strcmp(Z_STRVAL(new_key), "HTTP_ENV_VARS")==0)||
		    (strcmp(Z_STRVAL(new_key), "HTTP_SERVER_VARS")==0)||
		    (strcmp(Z_STRVAL(new_key), "HTTP_SESSION_VARS")==0)||
		    (strcmp(Z_STRVAL(new_key), "HTTP_COOKIE_VARS")==0)||
		    (strcmp(Z_STRVAL(new_key), "HTTP_RAW_POST_DATA")==0)) {
		    zval_dtor(&new_key);
		    return 0;
		}
	} else if (Z_STRVAL(new_key)[0] == '_') {
		if ((strcmp(Z_STRVAL(new_key), "_COOKIE")==0)||
		    (strcmp(Z_STRVAL(new_key), "_ENV")==0)||
		    (strcmp(Z_STRVAL(new_key), "_FILES")==0)||
		    (strcmp(Z_STRVAL(new_key), "_GET")==0)||
		    (strcmp(Z_STRVAL(new_key), "_POST")==0)||
		    (strcmp(Z_STRVAL(new_key), "_REQUEST")==0)||
		    (strcmp(Z_STRVAL(new_key), "_SESSION")==0)||
		    (strcmp(Z_STRVAL(new_key), "_SERVER")==0)) {
		    zval_dtor(&new_key);
		    return 0;
		}
	} else if (strcmp(Z_STRVAL(new_key), "GLOBALS")==0) {
		zval_dtor(&new_key);
		return 0;
	}

	zend_delete_global_variable(Z_STRVAL(new_key), Z_STRLEN(new_key) TSRMLS_CC);
	ZEND_SET_SYMBOL_WITH_LENGTH(&EG(symbol_table), Z_STRVAL(new_key), Z_STRLEN(new_key) + 1, *var, Z_REFCOUNT_PP(var) + 1, 0);

	zval_dtor(&new_key);
	return 0;
}
#else
static int copy_request_variable(void *pDest, int num_args, va_list args, zend_hash_key *hash_key)
{
	char *prefix, *new_key;
	uint prefix_len, new_key_len;
	zval **var = (zval **) pDest;
	TSRMLS_FETCH();

	if (num_args != 2) {
		return 0;
	}

	prefix = va_arg(args, char *);
	prefix_len = va_arg(args, uint);

	if (!prefix_len) {
		if (!hash_key->nKeyLength) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Numeric key detected - possible security hazard.");
			return 0;
		} else if (!strcmp(hash_key->arKey, "GLOBALS")) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Attempted GLOBALS variable overwrite.");
			return 0; 
		}
	}

	if (hash_key->nKeyLength) {
		new_key_len = prefix_len + hash_key->nKeyLength;
		new_key = (char *) emalloc(new_key_len);

		memcpy(new_key, prefix, prefix_len);
		memcpy(new_key+prefix_len, hash_key->arKey, hash_key->nKeyLength);
	} else {
		new_key_len = spprintf(&new_key, 0, "%s%ld", prefix, hash_key->h);
                new_key_len++;
	}

	if (php_varname_check(new_key, new_key_len-1, 0 TSRMLS_CC) == FAILURE) {
		zval_dtor(&new_key);
		return 0;
	}

	if (new_key[0] == 'H') {
		if ((strcmp(new_key, "HTTP_GET_VARS")==0)||
		    (strcmp(new_key, "HTTP_POST_VARS")==0)||
		    (strcmp(new_key, "HTTP_POST_FILES")==0)||
		    (strcmp(new_key, "HTTP_ENV_VARS")==0)||
		    (strcmp(new_key, "HTTP_SERVER_VARS")==0)||
		    (strcmp(new_key, "HTTP_SESSION_VARS")==0)||
		    (strcmp(new_key, "HTTP_COOKIE_VARS")==0)||
		    (strcmp(new_key, "HTTP_RAW_POST_DATA")==0)) {
		    efree(new_key);
		    return 0;
		}
	} else if (new_key[0] == '_') {
		if ((strcmp(new_key, "_COOKIE")==0)||
		    (strcmp(new_key, "_ENV")==0)||
		    (strcmp(new_key, "_FILES")==0)||
		    (strcmp(new_key, "_GET")==0)||
		    (strcmp(new_key, "_POST")==0)||
		    (strcmp(new_key, "_REQUEST")==0)||
		    (strcmp(new_key, "_SESSION")==0)||
		    (strcmp(new_key, "_SERVER")==0)) {
		    efree(new_key);
		    return 0;
		}
	} else if (strcmp(new_key, "GLOBALS")==0) {
		efree(new_key);
		return 0;
	}

#if PHP_MAJOR_VERSION > 5 || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 0)
	zend_delete_global_variable(new_key, new_key_len-1 TSRMLS_CC);
#else
	zend_hash_del(&EG(symbol_table), new_key, new_key_len-1);
#endif
	ZEND_SET_SYMBOL_WITH_LENGTH(&EG(symbol_table), new_key, new_key_len, *var, Z_REFCOUNT_PP(var)+1, 0);

	efree(new_key);
	return 0;
}
#endif

/* {{{ proto bool import_request_variables(string types [, string prefix])
   Import GET/POST/Cookie variables into the global scope */
PHP_FUNCTION(suhosin_import_request_variables)
{
#if PHP_VERSION_ID >= 50300	
	char *types;
	int types_len;
	zval *prefix = NULL;
	char *p;
	zend_bool ok = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|z/", &types, &types_len, &prefix) == FAILURE) {
		return;
	}

	if (ZEND_NUM_ARGS() > 1) {
		convert_to_string(prefix);

		if (Z_STRLEN_P(prefix) == 0) {
			php_error_docref(NULL TSRMLS_CC, E_NOTICE, "No prefix specified - possible security hazard");
		}
	} else {
		MAKE_STD_ZVAL(prefix);
		ZVAL_EMPTY_STRING(prefix);
	}

	for (p = types; p && *p; p++) {
		switch (*p) {

			case 'g':
			case 'G':
				zend_hash_apply_with_arguments(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_GET]) TSRMLS_CC, (apply_func_args_t) copy_request_variable, 1, prefix);
				ok = 1;
				break;

			case 'p':
			case 'P':
				zend_hash_apply_with_arguments(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_POST]) TSRMLS_CC, (apply_func_args_t) copy_request_variable, 1, prefix);
				zend_hash_apply_with_arguments(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_FILES]) TSRMLS_CC, (apply_func_args_t) copy_request_variable, 1, prefix);
				ok = 1;
				break;

			case 'c':
			case 'C':
				zend_hash_apply_with_arguments(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_COOKIE]) TSRMLS_CC, (apply_func_args_t) copy_request_variable, 1, prefix);
				ok = 1;
				break;
		}
	}

	if (ZEND_NUM_ARGS() < 2) {
		zval_ptr_dtor(&prefix);
	}
	RETURN_BOOL(ok);
#else
	zval **z_types, **z_prefix;
	char *types, *prefix;
	uint prefix_len;
	char *p;
	zend_bool ok = 0;

	switch (ZEND_NUM_ARGS()) {

		case 1:
			if (zend_get_parameters_ex(1, &z_types) == FAILURE) {
				RETURN_FALSE;
			}
			prefix = "";
			prefix_len = 0;
			break;

		case 2:
			if (zend_get_parameters_ex(2, &z_types, &z_prefix) == FAILURE) {
				RETURN_FALSE;
			}
			convert_to_string_ex(z_prefix);
			prefix = Z_STRVAL_PP(z_prefix);
			prefix_len = Z_STRLEN_PP(z_prefix);
			break;
	
		default:
			ZEND_WRONG_PARAM_COUNT();
	}

	if (prefix_len == 0) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "No prefix specified - possible security hazard");
	}

	convert_to_string_ex(z_types);
	types = Z_STRVAL_PP(z_types);

	for (p = types; p && *p; p++) {
		switch (*p) {
	
			case 'g':
			case 'G':
				zend_hash_apply_with_arguments(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_GET]), (apply_func_args_t) copy_request_variable, 2, prefix, prefix_len);
				ok = 1;
				break;
	
			case 'p':
			case 'P':
				zend_hash_apply_with_arguments(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_POST]), (apply_func_args_t) copy_request_variable, 2, prefix, prefix_len);
				zend_hash_apply_with_arguments(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_FILES]), (apply_func_args_t) copy_request_variable, 2, prefix, prefix_len);
				ok = 1;
				break;

			case 'c':
			case 'C':
				zend_hash_apply_with_arguments(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_COOKIE]), (apply_func_args_t) copy_request_variable, 2, prefix, prefix_len);
				ok = 1;
				break;
		}
	}
	RETURN_BOOL(ok);
#endif
}
/* }}} */

ZEND_BEGIN_ARG_INFO_EX(suhosin_arginfo_extract, 0, 0, 1)
	ZEND_ARG_INFO(ZEND_SEND_PREFER_REF, arg) /* ARRAY_INFO(0, arg, 0) */
	ZEND_ARG_INFO(0, extract_type)
	ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(suhosin_arginfo_import_request_variables, 0, 0, 1)
	ZEND_ARG_INFO(0, types)
	ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()

/* {{{ suhosin_ex_imp_functions[]
 */
function_entry suhosin_ex_imp_functions[] = {
	PHP_NAMED_FE(extract, PHP_FN(suhosin_extract), suhosin_arginfo_extract)
	PHP_NAMED_FE(import_request_variables, PHP_FN(suhosin_import_request_variables), suhosin_arginfo_import_request_variables)
	{NULL, NULL, NULL}
};
/* }}} */


void suhosin_hook_ex_imp()
{
	TSRMLS_FETCH();
	
	/* replace the extract and import_request_variables functions */
	zend_hash_del(CG(function_table), "extract", sizeof("extract"));
	zend_hash_del(CG(function_table), "import_request_variables", sizeof("import_request_variables"));
#ifndef ZEND_ENGINE_2
	zend_register_functions(suhosin_ex_imp_functions, NULL, MODULE_PERSISTENT TSRMLS_CC);
#else
	zend_register_functions(NULL, suhosin_ex_imp_functions, NULL, MODULE_PERSISTENT TSRMLS_CC);
#endif
 
	
	
			
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */


