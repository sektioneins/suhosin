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

/* $Id: php_suhosin.h,v 1.4 2008-01-13 22:50:37 sesser Exp $ */

#ifndef PHP_SUHOSIN_H
#define PHP_SUHOSIN_H

#define SUHOSIN_EXT_VERSION  "0.9.32.1"

/*#define SUHOSIN_DEBUG*/
#define SUHOSIN_LOG "/tmp/suhosin_log.txt"

#ifdef PHP_WIN32
#define SDEBUG
#else

#ifdef SUHOSIN_DEBUG
#define SDEBUG(msg...) \
    {FILE *f;f=fopen(SUHOSIN_LOG, "a+");if(f){fprintf(f,"[%u] ",getpid());fprintf(f, msg);fprintf(f,"\n");fclose(f);}}
#else
#define SDEBUG(...)
#endif    
#endif

extern zend_module_entry suhosin_module_entry;
#define phpext_suhosin_ptr &suhosin_module_entry

#ifdef PHP_WIN32
#define PHP_SUHOSIN_API __declspec(dllexport)
#else
#define PHP_SUHOSIN_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

/*#define STATIC static*/
#define STATIC

#define BYTE unsigned char       /* 8 bits  */
#define WORD unsigned int          /* 32 bits */

PHP_MINIT_FUNCTION(suhosin);
PHP_MSHUTDOWN_FUNCTION(suhosin);
PHP_RINIT_FUNCTION(suhosin);
PHP_RSHUTDOWN_FUNCTION(suhosin);
PHP_MINFO_FUNCTION(suhosin);

#include "ext/standard/basic_functions.h"

ZEND_BEGIN_MODULE_GLOBALS(suhosin)
	zend_uint in_code_type;
	long execution_depth;
	zend_bool simulation;
    zend_bool stealth;
	zend_bool protectkey;
	zend_bool executor_allow_symlink;
	char *filter_action;
	char *sql_user_prefix;
	char *sql_user_postfix;
	long	sql_comment;
	long	sql_opencomment;
	long	sql_union;
	long	sql_mselect;
	
	long max_execution_depth;
	zend_bool	abort_request;
	long executor_include_max_traversal;
        zend_bool executor_include_allow_writable_files;


	HashTable *include_whitelist;
	HashTable *include_blacklist;

	HashTable *func_whitelist;
	HashTable *func_blacklist;
	HashTable *eval_whitelist;
	HashTable *eval_blacklist;

	zend_bool executor_disable_eval;
	zend_bool executor_disable_emod;


/*	request variables */
	long  max_request_variables;
	long  cur_request_variables;
	long  max_varname_length;
	long  max_totalname_length;
	long  max_value_length;
	long  max_array_depth;
	long  max_array_index_length;
	zend_bool  disallow_nul;
	zend_bool  disallow_ws;
/*	cookie variables */
	long  max_cookie_vars;
	long  cur_cookie_vars;
	long  max_cookie_name_length;
	long  max_cookie_totalname_length;
	long  max_cookie_value_length;
	long  max_cookie_array_depth;
	long  max_cookie_array_index_length;
	zend_bool  disallow_cookie_nul;
	zend_bool  disallow_cookie_ws;
/*	get variables */
	long  max_get_vars;
	long  cur_get_vars;
	long  max_get_name_length;
	long  max_get_totalname_length;
	long  max_get_value_length;
	long  max_get_array_depth;
	long  max_get_array_index_length;
	zend_bool  disallow_get_nul;
	zend_bool  disallow_get_ws;
/*	post variables */
	long  max_post_vars;
	long  cur_post_vars;
	long  max_post_name_length;
	long  max_post_totalname_length;
	long  max_post_value_length;
	long  max_post_array_depth;
	long  max_post_array_index_length;
	zend_bool  disallow_post_nul;
	zend_bool  disallow_post_ws;

/*	fileupload */
	long  upload_limit;
	long  num_uploads;
	zend_bool  upload_disallow_elf;
	zend_bool  upload_disallow_binary;
	zend_bool  upload_remove_binary;
	char *upload_verification_script;
        
        zend_bool  no_more_variables;
        zend_bool  no_more_get_variables;
        zend_bool  no_more_post_variables;
        zend_bool  no_more_cookie_variables;
        zend_bool  no_more_uploads;



/*	log */
	zend_bool log_use_x_forwarded_for;
	long	log_syslog;
	long	log_syslog_facility;
	long	log_syslog_priority;
	long	log_script;
	long	log_sapi;
	char	*log_scriptname;
	long	log_phpscript;
	char	*log_phpscriptname;
	zend_bool log_phpscript_is_safe;
	long	log_file;
	char	*log_filename;

/*	header handler */
	zend_bool allow_multiheader;

/*	mailprotect */
	long	mailprotect;
	
/*	memory_limit */
	long	memory_limit;
	long 	hard_memory_limit;

/*  sqlprotect */
	zend_bool sql_bailout_on_error;

	int (*old_php_body_write)(const char *str, unsigned int str_length TSRMLS_DC);

/*	session */
	void	*s_module;
	int 	(*old_s_read)(void **mod_data, const char *key, char **val, int *vallen TSRMLS_DC);
	int	(*old_s_write)(void **mod_data, const char *key, const char *val, const int vallen TSRMLS_DC);
	int	(*old_s_destroy)(void **mod_data, const char *key TSRMLS_DC);

	BYTE fi[24],ri[24];
        WORD fkey[120];
        WORD rkey[120];
	
	zend_bool	session_encrypt;
	char*	session_cryptkey;
	zend_bool	session_cryptua;
	zend_bool	session_cryptdocroot;
	long		session_cryptraddr;
	long		session_checkraddr;
	
	long	session_max_id_length;
	
	char*	decrypted_cookie;
    char*	raw_cookie;
	zend_bool	cookie_encrypt;
	char*	cookie_cryptkey;
	zend_bool	cookie_cryptua;
	zend_bool	cookie_cryptdocroot;
	long		cookie_cryptraddr;
	long		cookie_checkraddr;
	HashTable *cookie_plainlist;
	HashTable *cookie_cryptlist;
	
	zend_bool	coredump;
	zend_bool	apc_bug_workaround;
	zend_bool	already_scanned;
        zend_bool       do_not_scan;
	
	zend_bool	server_encode;
	zend_bool	server_strip;
	
	zend_bool	disable_display_errors;

	php_uint32   r_state[625];
	php_uint32   *r_next;
	int          r_left;
    zend_bool    srand_ignore;
    zend_bool    mt_srand_ignore;
	php_uint32   mt_state[625];
	php_uint32   *mt_next;
	int          mt_left;

	zend_bool r_is_seeded; 
	zend_bool mt_is_seeded;

	/* PERDIR Handling */
        char *perdir;
        zend_bool log_perdir;
        zend_bool exec_perdir;
        zend_bool get_perdir;
        zend_bool post_perdir;
        zend_bool cookie_perdir;
        zend_bool request_perdir;
        zend_bool upload_perdir;
        zend_bool sql_perdir;
        zend_bool misc_perdir;

ZEND_END_MODULE_GLOBALS(suhosin)

#ifdef ZTS
#define SUHOSIN_G(v) TSRMG(suhosin_globals_id, zend_suhosin_globals *, v)
#else
#define SUHOSIN_G(v) (suhosin_globals.v)
#endif

#ifndef ZEND_INI_STAGE_HTACCESS
#define ZEND_INI_STAGE_HTACCESS (1<<5)
#endif
 
#ifndef ZEND_ENGINE_2
#define OnUpdateLong OnUpdateInt
#define zend_symtable_find zend_hash_find
#define zend_symtable_update zend_hash_update
#define zend_symtable_exists zend_hash_exists
#endif


/* Error Constants */
#ifndef S_MEMORY
#define S_MEMORY			(1<<0L)
#define S_MISC				(1<<1L)
#define S_VARS				(1<<2L)
#define S_FILES				(1<<3L)
#define S_INCLUDE			(1<<4L)
#define S_SQL				(1<<5L)
#define S_EXECUTOR			(1<<6L)
#define S_MAIL				(1<<7L)
#define S_SESSION			(1<<8L)
#define S_INTERNAL			(1<<29L)
#define S_ALL (S_MEMORY | S_VARS | S_INCLUDE | S_FILES | S_MAIL | S_SESSION | S_MISC | S_SQL | S_EXECUTOR)
#endif

#define SUHOSIN_NORMAL	0
#define SUHOSIN_EVAL	1

#define SUHOSIN_FLAG_CREATED_BY_EVAL 1
#define SUHOSIN_FLAG_NOT_EVALED_CODE 2

ZEND_EXTERN_MODULE_GLOBALS(suhosin)

static inline char *
suhosin_str_tolower_dup(const char *source, unsigned int length)
{
	register char *dup = estrndup(source, length);
	zend_str_tolower(dup, length);
	return dup;
}

/* functions */
PHP_SUHOSIN_API void suhosin_log(int loglevel, char *fmt, ...);
char *suhosin_encrypt_string(char *str, int len, char *var, int vlen, char *key TSRMLS_DC);
char *suhosin_decrypt_string(char *str, int padded_len, char *var, int vlen, char *key, int *orig_len, int check_ra TSRMLS_DC);
char *suhosin_generate_key(char *key, zend_bool ua, zend_bool dr, long raddr, char *cryptkey TSRMLS_DC);
char *suhosin_cookie_decryptor(TSRMLS_D);
void suhosin_hook_post_handlers(TSRMLS_D);
void suhosin_hook_register_server_variables();
void suhosin_hook_header_handler();
void suhosin_unhook_header_handler();
void suhosin_hook_session(TSRMLS_D);
void suhosin_unhook_session(TSRMLS_D);
void suhosin_hook_crypt();
void suhosin_hook_sha256();
void suhosin_hook_ex_imp();
void suhosin_hook_treat_data();
void suhosin_hook_memory_limit();
void suhosin_hook_execute(TSRMLS_D);
void suhosin_unhook_execute();
void suhosin_aes_gentables();
void suhosin_aes_gkey(int nb,int nk,char *key TSRMLS_DC);
void suhosin_aes_encrypt(char *buff TSRMLS_DC);
void suhosin_aes_decrypt(char *buff TSRMLS_DC);
unsigned int suhosin_input_filter(int arg, char *var, char **val, unsigned int val_len, unsigned int *new_val_len TSRMLS_DC);
unsigned int suhosin_input_filter_wrapper(int arg, char *var, char **val, unsigned int val_len, unsigned int *new_val_len TSRMLS_DC);
extern unsigned int (*old_input_filter)(int arg, char *var, char **val, unsigned int val_len, unsigned int *new_val_len TSRMLS_DC);
void normalize_varname(char *varname);
int suhosin_rfc1867_filter(unsigned int event, void *event_data, void **extra TSRMLS_DC);
void suhosin_bailout(TSRMLS_D);

/* Add pseudo refcount macros for PHP version < 5.3 */
#ifndef Z_REFCOUNT_PP

#define Z_REFCOUNT_PP(ppz)		Z_REFCOUNT_P(*(ppz))
#define Z_SET_REFCOUNT_PP(ppz, rc)	Z_SET_REFCOUNT_P(*(ppz), rc)
#define Z_ADDREF_PP(ppz)		Z_ADDREF_P(*(ppz))
#define Z_DELREF_PP(ppz)		Z_DELREF_P(*(ppz))
#define Z_ISREF_PP(ppz)			Z_ISREF_P(*(ppz))
#define Z_SET_ISREF_PP(ppz)		Z_SET_ISREF_P(*(ppz))
#define Z_UNSET_ISREF_PP(ppz)		Z_UNSET_ISREF_P(*(ppz))
#define Z_SET_ISREF_TO_PP(ppz, isref)	Z_SET_ISREF_TO_P(*(ppz), isref)

#define Z_REFCOUNT_P(pz)		zval_refcount_p(pz)
#define Z_SET_REFCOUNT_P(pz, rc)	zval_set_refcount_p(pz, rc)
#define Z_ADDREF_P(pz)			zval_addref_p(pz)
#define Z_DELREF_P(pz)			zval_delref_p(pz)
#define Z_ISREF_P(pz)			zval_isref_p(pz)
#define Z_SET_ISREF_P(pz)		zval_set_isref_p(pz)
#define Z_UNSET_ISREF_P(pz)		zval_unset_isref_p(pz)
#define Z_SET_ISREF_TO_P(pz, isref)	zval_set_isref_to_p(pz, isref)

#define Z_REFCOUNT(z)			Z_REFCOUNT_P(&(z))
#define Z_SET_REFCOUNT(z, rc)		Z_SET_REFCOUNT_P(&(z), rc)
#define Z_ADDREF(z)			Z_ADDREF_P(&(z))
#define Z_DELREF(z)			Z_DELREF_P(&(z))
#define Z_ISREF(z)			Z_ISREF_P(&(z))
#define Z_SET_ISREF(z)			Z_SET_ISREF_P(&(z))
#define Z_UNSET_ISREF(z)		Z_UNSET_ISREF_P(&(z))
#define Z_SET_ISREF_TO(z, isref)	Z_SET_ISREF_TO_P(&(z), isref)

#if defined(__GNUC__)
#define zend_always_inline inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define zend_always_inline __forceinline
#else
#define zend_always_inline inline
#endif

static zend_always_inline zend_uint zval_refcount_p(zval* pz) {
	return pz->refcount;
}

static zend_always_inline zend_uint zval_set_refcount_p(zval* pz, zend_uint rc) {
	return pz->refcount = rc;
}

static zend_always_inline zend_uint zval_addref_p(zval* pz) {
	return ++pz->refcount;
}

static zend_always_inline zend_uint zval_delref_p(zval* pz) {
	return --pz->refcount;
}

static zend_always_inline zend_bool zval_isref_p(zval* pz) {
	return pz->is_ref;
}

static zend_always_inline zend_bool zval_set_isref_p(zval* pz) {
	return pz->is_ref = 1;
}

static zend_always_inline zend_bool zval_unset_isref_p(zval* pz) {
	return pz->is_ref = 0;
}

static zend_always_inline zend_bool zval_set_isref_to_p(zval* pz, zend_bool isref) {
	return pz->is_ref = isref;
}

#else

#define PHP_ATLEAST_5_3   true

#endif


#endif	/* PHP_SUHOSIN_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
