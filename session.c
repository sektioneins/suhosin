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
  | Authors: Stefan Esser <sesser@sektioneins.de>                        |
  |          Ben Fuhrmannek <ben.fuhrmannek@sektioneins.de>              |
  +----------------------------------------------------------------------+
*/
/*
  $Id: session.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "TSRM.h"
#include "SAPI.h"
#include "php_ini.h"
#include "php_suhosin.h"
#include "ext/standard/php_smart_str.h"
#include "ext/standard/php_var.h"

#include <fcntl.h>

#if defined(HAVE_HASH_EXT) && !defined(COMPILE_DL_HASH)
# include "ext/hash/php_hash.h"
#endif

#ifdef HAVE_PHP_SESSION
#include "ext/session/php_session.h"

#ifdef ZTS
static ts_rsrc_id session_globals_id = 0;
#define SESSION_G(v) TSRMG(session_globals_id, php_ps_globals *, v)
#else
static php_ps_globals *session_globals = NULL;
#define SESSION_G(v) (session_globals->v)
#endif

ps_serializer *(*suhosin_find_ps_serializer)(char *name TSRMLS_DC) = NULL;

#define PS_DELIMITER '|'
#define PS_UNDEF_MARKER '!'

int suhosin_session_encode(char **newstr, int *newlen TSRMLS_DC)
{
	smart_str buf = {0};
	php_serialize_data_t var_hash;
	PS_ENCODE_VARS;

	PHP_VAR_SERIALIZE_INIT(var_hash);

	PS_ENCODE_LOOP(
			smart_str_appendl(&buf, key, key_length);
			if (key[0] == PS_UNDEF_MARKER || memchr(key, PS_DELIMITER, key_length)) {
				PHP_VAR_SERIALIZE_DESTROY(var_hash);
				smart_str_free(&buf);
				return FAILURE;
			}
			smart_str_appendc(&buf, PS_DELIMITER);

			php_var_serialize(&buf, struc, &var_hash TSRMLS_CC);
		} else {
			smart_str_appendc(&buf, PS_UNDEF_MARKER);
			smart_str_appendl(&buf, key, key_length);
			smart_str_appendc(&buf, PS_DELIMITER);
	);

	if (newlen) {
		*newlen = buf.len;
	}
	smart_str_0(&buf);
	*newstr = buf.c;

	PHP_VAR_SERIALIZE_DESTROY(var_hash);
	return SUCCESS;
}

static void suhosin_send_cookie(TSRMLS_D)
{
	int  * session_send_cookie = &SESSION_G(send_cookie);
	char * base;
	zend_ini_entry *ini_entry;

	/* The following is requires to be 100% compatible to PHP
	   versions where the hash extension is not available by default */
	if (zend_hash_find(EG(ini_directives), "session.hash_bits_per_character", sizeof("session.hash_bits_per_character"), (void **) &ini_entry) == SUCCESS) {
#ifndef ZTS
		base = (char *) ini_entry->mh_arg2;
#else
		base = (char *) ts_resource(*((int *) ini_entry->mh_arg2));
#endif
		session_send_cookie = (int *) (base+(size_t) ini_entry->mh_arg1+sizeof(long));
	}
	*session_send_cookie = 1;
}



static int (*old_OnUpdateSaveHandler)(zend_ini_entry *entry, char *new_value, uint new_value_length, void *mh_arg1, void *mh_arg2, void *mh_arg3, int stage TSRMLS_DC) = NULL;
static int (*old_SessionRINIT)(INIT_FUNC_ARGS) = NULL;

static int suhosin_hook_s_read(void **mod_data, const char *key, char **val, int *vallen TSRMLS_DC)
{
	int r;

	int i;char *v,*KEY=(char *)key;

	/* protect session vars */
/*  if (SESSION_G(http_session_vars) && SESSION_G(http_session_vars)->type == IS_ARRAY) {
		SESSION_G(http_session_vars)->refcount++;
	}*/

	/* protect dumb session handlers */
	if (key == NULL || !key[0] ||
		(*mod_data == NULL
		&& !SESSION_G(mod_user_implemented)
		)) {
regenerate:
		SDEBUG("regenerating key is %s", key);
		KEY = SESSION_G(id) = SESSION_G(mod)->s_create_sid(&SESSION_G(mod_data), NULL TSRMLS_CC);
		suhosin_send_cookie(TSRMLS_C);
	} else if (strlen(key) > SUHOSIN_G(session_max_id_length)) {
		suhosin_log(S_SESSION, "session id ('%s') exceeds maximum length - regenerating", KEY);
		if (!SUHOSIN_G(simulation)) {
			goto regenerate;
		}
	}

	r = SUHOSIN_G(old_s_read)(mod_data, KEY, val, vallen TSRMLS_CC);

	if (r == SUCCESS && SUHOSIN_G(session_encrypt) && *vallen > 0) {
		char cryptkey[33];

		SUHOSIN_G(do_not_scan) = 1;
		suhosin_generate_key(SUHOSIN_G(session_cryptkey), SUHOSIN_G(session_cryptua), SUHOSIN_G(session_cryptdocroot), SUHOSIN_G(session_cryptraddr), (char *)&cryptkey TSRMLS_CC);

		v = *val;
		i = *vallen;
		*val = suhosin_decrypt_string(v, i, "", 0, (char *)&cryptkey, vallen, SUHOSIN_G(session_checkraddr) TSRMLS_CC);
		SUHOSIN_G(do_not_scan) = 0;
	if (*val == NULL) {
		*val = estrndup("", 0);
		*vallen = 0;
	}
		efree(v);
	}

	return r;
}

static int suhosin_hook_s_write(void **mod_data, const char *key, const char *val, const int vallen TSRMLS_DC)
{
	int r;
/*  int nullify = 0;*/
	char *v = (char *)val;

	/* protect dumb session handlers */
	if (key == NULL || !key[0] || val == NULL || strlen(key) > SUHOSIN_G(session_max_id_length) ||
		(*mod_data == NULL
		&& !SESSION_G(mod_user_implemented)
		)) {
		r = FAILURE;
		goto return_write;
	}

	r = vallen;

	if (r > 0 && SUHOSIN_G(session_encrypt)) {
		char cryptkey[33];

		SUHOSIN_G(do_not_scan) = 1;

		suhosin_generate_key(SUHOSIN_G(session_cryptkey), SUHOSIN_G(session_cryptua), SUHOSIN_G(session_cryptdocroot), SUHOSIN_G(session_cryptraddr), (char *)&cryptkey TSRMLS_CC);

		v = suhosin_encrypt_string(v, vallen, "", 0, (char *)&cryptkey TSRMLS_CC);

		SUHOSIN_G(do_not_scan) = 0;
		r = strlen(v);
	}

	r = SUHOSIN_G(old_s_write)(mod_data, key, v, r TSRMLS_CC);

return_write:
	/* protect session vars */
/*  if (SESSION_G(http_session_vars) && SESSION_G(http_session_vars)->type == IS_ARRAY) {
		if (SESSION_G(http_session_vars)->refcount==1) {
			nullify = 1;
		}
		zval_ptr_dtor(&SESSION_G(http_session_vars));
		if (nullify) {
			suhosin_log(S_SESSION, "possible session variables double free attack stopped");
			SESSION_G(http_session_vars) = NULL;
		}
	}*/

	return r;
}

static int suhosin_hook_s_destroy(void **mod_data, const char *key TSRMLS_DC)
{
	int r;

	/* protect dumb session handlers */
	if (key == NULL || !key[0] || strlen(key) > SUHOSIN_G(session_max_id_length) ||
		(*mod_data == NULL
		&& !SESSION_G(mod_user_implemented)
		)) {
		return FAILURE;
	}

	r = SUHOSIN_G(old_s_destroy)(mod_data, key TSRMLS_CC);

	return r;
}

static void suhosin_hook_session_module(TSRMLS_D)
{
	ps_module *old_mod = SESSION_G(mod), *mod;

	if (old_mod == NULL || SUHOSIN_G(s_module) == old_mod) {
		return;
	}

	if (SUHOSIN_G(s_module) == NULL) {
		SUHOSIN_G(s_module) = mod = malloc(sizeof(ps_module));
		if (mod == NULL) {
			return;
		}
	}

	SUHOSIN_G(s_original_mod) = old_mod;

	mod = SUHOSIN_G(s_module);
	memcpy(mod, old_mod, sizeof(ps_module));

	SUHOSIN_G(old_s_read) = mod->s_read;
	mod->s_read = suhosin_hook_s_read;
	SUHOSIN_G(old_s_write) = mod->s_write;
	mod->s_write = suhosin_hook_s_write;
	SUHOSIN_G(old_s_destroy) = mod->s_destroy;
	mod->s_destroy = suhosin_hook_s_destroy;

	SESSION_G(mod) = mod;
}

static PHP_INI_MH(suhosin_OnUpdateSaveHandler)
{
	int r;

	if (stage == PHP_INI_STAGE_RUNTIME && SESSION_G(session_status) == php_session_none && SUHOSIN_G(s_original_mod)
		&& strcmp(new_value, "user") == 0 && strcmp(((ps_module*)SUHOSIN_G(s_original_mod))->s_name, "user") == 0) {
		return SUCCESS;
	}

	SESSION_G(mod) = SUHOSIN_G(s_original_mod);

	r = old_OnUpdateSaveHandler(entry, new_value, new_value_length, mh_arg1, mh_arg2, mh_arg3, stage TSRMLS_CC);

	suhosin_hook_session_module(TSRMLS_C);

	return r;
}


static int suhosin_hook_session_RINIT(INIT_FUNC_ARGS)
{
	if (SESSION_G(mod) == NULL) {
		char *value = zend_ini_string("session.save_handler", sizeof("session.save_handler"), 0);

		if (value) {
			suhosin_OnUpdateSaveHandler(NULL, value, strlen(value), NULL, NULL, NULL, 0 TSRMLS_CC);
		}
	}
	return old_SessionRINIT(INIT_FUNC_ARGS_PASSTHRU);
}

void suhosin_hook_session(TSRMLS_D)
{
	ps_serializer *serializer;
	zend_ini_entry *ini_entry;
	zend_module_entry *module;
#ifdef ZTS
	ts_rsrc_id *ps_globals_id_ptr;
#endif

	if (zend_hash_find(&module_registry, "session", sizeof("session"), (void**)&module) == FAILURE) {
		return;
	}
	/* retrieve globals from module entry struct if possible */
#ifdef ZTS
	if (session_globals_id == 0) {
	session_globals_id = *module->globals_id_ptr;
	}
#else
	if (session_globals == NULL) {
	session_globals = module->globals_ptr;
	}
#endif

	if (old_OnUpdateSaveHandler != NULL) {
		return;
	}

	/* hook request startup function of session module */
	old_SessionRINIT = module->request_startup_func;
	module->request_startup_func = suhosin_hook_session_RINIT;

	/* retrieve pointer to session.save_handler ini entry */
	if (zend_hash_find(EG(ini_directives), "session.save_handler", sizeof("session.save_handler"), (void **) &ini_entry) == FAILURE) {
		return;
	}
	SUHOSIN_G(s_module) = NULL;

	/* replace OnUpdateMemoryLimit handler */
	old_OnUpdateSaveHandler = ini_entry->on_modify;
	ini_entry->on_modify = suhosin_OnUpdateSaveHandler;

	suhosin_hook_session_module(TSRMLS_C);

	/* Protect the PHP serializer from ! attacks */
	serializer = (ps_serializer *) SESSION_G(serializer);
	if (serializer != NULL && strcmp(serializer->name, "php")==0) {
		serializer->encode = suhosin_session_encode;
	}

	/* increase session identifier entropy */
	if (SESSION_G(entropy_length) == 0 || SESSION_G(entropy_file) == NULL) {
#ifndef PHP_WIN32
		/* ensure that /dev/urandom exists */
		int fd = VCWD_OPEN("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			close(fd);
			SESSION_G(entropy_length) = 16;
			SESSION_G(entropy_file) = pestrdup("/dev/urandom", 1);
		}
#endif
	}
}

void suhosin_unhook_session(TSRMLS_D)
{
	if (old_OnUpdateSaveHandler != NULL) {
		zend_ini_entry *ini_entry;

		/* retrieve pointer to session.save_handler ini entry */
		if (zend_hash_find(EG(ini_directives), "session.save_handler", sizeof("session.save_handler"), (void **) &ini_entry) == FAILURE) {
			return;
		}
		ini_entry->on_modify = old_OnUpdateSaveHandler;

		old_OnUpdateSaveHandler = NULL;
	}

}

#else /* HAVE_PHP_SESSION */

#warning BUILDING SUHOSIN WITHOUT SESSION SUPPORT

void suhosin_hook_session(TSRMLS_D)
{
}

void suhosin_unhook_session(TSRMLS_D)
{
}

#endif /* HAVE_PHP_SESSION */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
