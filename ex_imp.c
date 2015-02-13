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

	if (suhosin_is_protected_varname(var_name, len)) {
		return 0;
	}
	
	return 1;
}


/* {{{ proto int extract(array var_array [, int extract_type [, string prefix]])
   Imports variables into symbol table from an array */
PHP_FUNCTION(suhosin_extract)
{
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
}
/* }}} */



ZEND_BEGIN_ARG_INFO_EX(suhosin_arginfo_extract, 0, 0, 1)
	ZEND_ARG_INFO(ZEND_SEND_PREFER_REF, arg) /* ARRAY_INFO(0, arg, 0) */
	ZEND_ARG_INFO(0, extract_type)
	ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()


/* {{{ suhosin_ex_imp_functions[]
 */
zend_function_entry suhosin_ex_imp_functions[] = {
	PHP_NAMED_FE(extract, PHP_FN(suhosin_extract), suhosin_arginfo_extract)
	{NULL, NULL, NULL}
};
/* }}} */

void suhosin_hook_ex_imp(TSRMLS_D)
{
	/* replace the extract and import_request_variables functions */
	zend_hash_del(CG(function_table), "extract", sizeof("extract"));
	zend_register_functions(NULL, suhosin_ex_imp_functions, NULL, MODULE_PERSISTENT TSRMLS_CC);
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */


