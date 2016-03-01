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
  | Author: Juergen Pabel <jpabel@akkaya.de>                             |
  +----------------------------------------------------------------------+
*/

#ifdef SUHOSIN_EXPERIMENTAL
#include <stdio.h>
#include "php.h"
#include "php_suhosin.h"
#include "sha256.h"

static char cryptkey[32];

/* {{{ proto string secureconfig_encrypt(string plaintext)
   Encrypt a configuration value using the configured cryptographic key */
static PHP_FUNCTION(suhosin_secureconfig_encrypt)
{
	char *plaintext, *ciphertext;
	int plaintext_len, ciphertext_len;
	int i;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &plaintext, &plaintext_len) == FAILURE) {
		return;
	}
	ciphertext = suhosin_encrypt_string(plaintext, plaintext_len, "", 0, cryptkey TSRMLS_CC);
	if(ciphertext == NULL) {
		return;
	}
	ciphertext_len = strlen(ciphertext);
	/* undo suhosin_encrypt_string()'s base64 alphabet transformation */
	for (i=0; i<ciphertext_len; i++) {
		switch (ciphertext[i]) {
			case '-': ciphertext[i]='/'; break;
			case '.': ciphertext[i]='='; break;
			case '_': ciphertext[i]='+'; break;
		}
	}
	RETURN_STRINGL((char *)ciphertext, ciphertext_len, 1);
}

/* }}} */


/* {{{ proto string secureconfig_decrypt(string ciphertext)
   Decrypt a configuration value using the configured cryptographic key */
static PHP_FUNCTION(suhosin_secureconfig_decrypt)
{
	char *plaintext, *ciphertext;
	int plaintext_len, ciphertext_len;
	int i;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &ciphertext, &ciphertext_len) == FAILURE) {
		return;
	}

	/* redo suhosin_encrypt_string()'s base64 alphabet transformation */
	for (i=0; i<ciphertext_len; i++) {
		switch (ciphertext[i]) {
			case '/': ciphertext[i]='-'; break;
			case '=': ciphertext[i]='.'; break;
			case '+': ciphertext[i]='_'; break;
		}
	}
	plaintext = suhosin_decrypt_string(ciphertext, ciphertext_len, "", 0, cryptkey, &plaintext_len, 0 TSRMLS_CC);
	if(plaintext == NULL || plaintext_len <= 0) {
		return;
	}
	RETURN_STRINGL((char *)plaintext, plaintext_len, 1);
}

/* }}} */


/* {{{ suhosin_secureconfig_functions[]
 */
static function_entry suhosin_secureconfig_functions[] = {
	PHP_NAMED_FE(secureconfig_encrypt, PHP_FN(suhosin_secureconfig_encrypt), NULL)
	PHP_NAMED_FE(secureconfig_decrypt, PHP_FN(suhosin_secureconfig_decrypt), NULL)
	{NULL, NULL, NULL}
};
/* }}} */


void suhosin_hook_secureconfig(TSRMLS_D)
{
	char* key;
	suhosin_SHA256_CTX ctx;

	// TSRMLS_FETCH();
	
	/* check if we already have secureconfig support */
	if (zend_hash_exists(CG(function_table), "secureconfig_encrypt", sizeof("secureconfig_encrypt"))) {
		return;		
	}

	key = SUHOSIN_G(secureconfig_cryptkey);
	if (key != NULL) {
		suhosin_SHA256Init(&ctx);
		suhosin_SHA256Update(&ctx, (unsigned char*)key, strlen(key));
		suhosin_SHA256Final((unsigned char *)cryptkey, &ctx);
	} else {
		memset(cryptkey, 0x55 /*fallback key with alternating bits*/, 32);
	}

	/* add the secureconfig functions */
#ifndef ZEND_ENGINE_2
	zend_register_functions(suhosin_secureconfig_functions, NULL, MODULE_PERSISTENT TSRMLS_CC);
#else
	zend_register_functions(NULL, suhosin_secureconfig_functions, NULL, MODULE_PERSISTENT TSRMLS_CC);
#endif
}

#endif /* SUHOSIN_EXPERIMENTAL */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
