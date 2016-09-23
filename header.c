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
  $Id: header.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "php_suhosin.h"
#include "SAPI.h"
#include "php_variables.h"

static int (*orig_header_handler)(sapi_header_struct *sapi_header, sapi_header_op_enum op, sapi_headers_struct *sapi_headers TSRMLS_DC) = NULL;

char *suhosin_encrypt_single_cookie(char *name, int name_len, char *value, int value_len, char *key TSRMLS_DC)
{
	char *buf, *buf2, *d, *d_url;
	int l;

	buf = estrndup(name, name_len);


	name_len = php_url_decode(buf, name_len);
	normalize_varname(buf);
	name_len = strlen(buf);

	if (SUHOSIN_G(cookie_plainlist)) {
		if (zend_hash_exists(SUHOSIN_G(cookie_plainlist), buf, name_len+1)) {
encrypt_return_plain:
			efree(buf);
			return estrndup(value, value_len);
		}
	} else if (SUHOSIN_G(cookie_cryptlist)) {
		if (!zend_hash_exists(SUHOSIN_G(cookie_cryptlist), buf, name_len+1)) {
			goto encrypt_return_plain;
		}
	}

	buf2 = estrndup(value, value_len);

	value_len = php_url_decode(buf2, value_len);

	d = suhosin_encrypt_string(buf2, value_len, buf, name_len, key TSRMLS_CC);
	d_url = php_url_encode(d, strlen(d), &l);
	efree(d);
	efree(buf);
	efree(buf2);
	return d_url;
}

char *suhosin_decrypt_single_cookie(char *name, int name_len, char *value, int value_len, char *key, char **where TSRMLS_DC)
{
	int o_name_len = name_len;
	char *buf, *buf2, *d, *d_url;
	int l;

	buf = estrndup(name, name_len);

	name_len = php_url_decode(buf, name_len);
	normalize_varname(buf);
	name_len = strlen(buf);

	if (SUHOSIN_G(cookie_plainlist)) {
		if (zend_hash_exists(SUHOSIN_G(cookie_plainlist), buf, name_len+1)) {
decrypt_return_plain:
			efree(buf);
			memcpy(*where, name, o_name_len);
			*where += o_name_len;
			**where = '='; *where +=1;
			memcpy(*where, value, value_len);
			*where += value_len;
			return *where;
		}
	} else if (SUHOSIN_G(cookie_cryptlist)) {
		if (!zend_hash_exists(SUHOSIN_G(cookie_cryptlist), buf, name_len+1)) {
			goto decrypt_return_plain;
		}
	}


	buf2 = estrndup(value, value_len);

	value_len = php_url_decode(buf2, value_len);

	d = suhosin_decrypt_string(buf2, value_len, buf, name_len, key, &l, SUHOSIN_G(cookie_checkraddr) TSRMLS_CC);
	if (d == NULL) {
		goto skip_cookie;
	}
	d_url = php_url_encode(d, l, &l);
	efree(d);
	memcpy(*where, name, o_name_len);
	*where += o_name_len;
	**where = '=';*where += 1;
	memcpy(*where, d_url, l);
	*where += l;
	efree(d_url);
skip_cookie:
	efree(buf);
	efree(buf2);
	return *where;
}

/* {{{ suhosin_cookie_decryptor
 */
char *suhosin_cookie_decryptor(TSRMLS_D)
{
	char *raw_cookie = SG(request_info).cookie_data;
	char *decrypted, *ret, *var, *val, *tmp;
	int j;
	char cryptkey[33];

	/*
	if (...deactivated...) {
		return estrdup(raw_cookie);
	}
	*/

	suhosin_generate_key(SUHOSIN_G(cookie_cryptkey), SUHOSIN_G(cookie_cryptua), SUHOSIN_G(cookie_cryptdocroot), SUHOSIN_G(cookie_cryptraddr), (char *)&cryptkey TSRMLS_CC);

	ret = decrypted = emalloc(strlen(raw_cookie)*4+1);
	raw_cookie = estrdup(raw_cookie);
	SUHOSIN_G(raw_cookie) = estrdup(raw_cookie);


	j = 0; tmp = raw_cookie;
	while (*tmp) {
		char *d_url;int varlen;
		while (*tmp == '\t' || *tmp == ' ') tmp++;
		var = tmp;
		while (*tmp && *tmp != ';' && *tmp != '=') tmp++;

		varlen = tmp-var;
		/*memcpy(decrypted, var, varlen);
		decrypted += varlen;*/
		if (*tmp == 0) break;

		if (*tmp++ == ';') {
			*decrypted++ = ';';
			continue;
		}

		/**decrypted++ = '=';*/

		val = tmp;
		while (*tmp && *tmp != ';') tmp++;

		d_url = suhosin_decrypt_single_cookie(var, varlen, val, tmp-val, (char *)&cryptkey, &decrypted TSRMLS_CC);
		if (*tmp == ';') {
			*decrypted++ = ';';
		}

		if (*tmp == 0) break;
		tmp++;
	}
	*decrypted++ = 0;
	ret = erealloc(ret, decrypted-ret);

	SUHOSIN_G(decrypted_cookie) = ret;
	efree(raw_cookie);

	return ret;
}
/* }}} */

/* {{{ suhosin_header_handler
 */
int suhosin_header_handler(sapi_header_struct *sapi_header, sapi_header_op_enum op, sapi_headers_struct *sapi_headers TSRMLS_DC)
{
	int retval = SAPI_HEADER_ADD, i;
	char *tmp;

	if (op != SAPI_HEADER_ADD && op != SAPI_HEADER_REPLACE) {
		goto suhosin_skip_header_handling;
	}

	if (sapi_header && sapi_header->header) {

		tmp = sapi_header->header;

		for (i=0; i<sapi_header->header_len; i++, tmp++) {
			if (tmp[0] == 0) {
				char *fname = (char *)get_active_function_name(TSRMLS_C);

				if (!fname) {
					fname = "unknown";
				}

				suhosin_log(S_MISC, "%s() - wanted to send a HTTP header with an ASCII NUL in it", fname);
				if (!SUHOSIN_G(simulation)) {
					sapi_header->header_len = i;
				}
			}
			if (SUHOSIN_G(allow_multiheader)) {
				continue;
			} else if ((tmp[0] == '\r' && (tmp[1] != '\n' || i == 0)) ||
			   (tmp[0] == '\n' && (i == sapi_header->header_len-1 || i == 0 || (tmp[1] != ' ' && tmp[1] != '\t')))) {
				char *fname = (char *)get_active_function_name(TSRMLS_C);

				if (!fname) {
					fname = "unknown";
				}

				suhosin_log(S_MISC, "%s() - wanted to send multiple HTTP headers at once", fname);
				if (!SUHOSIN_G(simulation)) {
					sapi_header->header_len = i;
					tmp[0] = 0;
				}
			}
		}
	}

	/* Handle a potential cookie */

	if (SUHOSIN_G(cookie_encrypt) && (strncasecmp("Set-Cookie:", sapi_header->header, sizeof("Set-Cookie:")-1) == 0)) {

		char *start, *end, *rend, *tmp;
		char *name, *value;
		int nlen, vlen, len, tlen;
		char cryptkey[33];

		suhosin_generate_key(SUHOSIN_G(cookie_cryptkey), SUHOSIN_G(cookie_cryptua), SUHOSIN_G(cookie_cryptdocroot), SUHOSIN_G(cookie_cryptraddr), (char *)&cryptkey TSRMLS_CC);
		start = estrndup(sapi_header->header, sapi_header->header_len);
		rend = end = start + sapi_header->header_len;

		tmp = memchr(start, ';', end-start);
		if (tmp != NULL) {
			end = tmp;
		}

		tmp = start + sizeof("Set-Cookie:") - 1;
		while (tmp < end && tmp[0]==' ') {
			tmp++;
		}
		name = tmp;
		nlen = end-name;
		tmp = memchr(name, '=', nlen);
		if (tmp == NULL) {
			value = end;
		} else {
			value = tmp+1;
			nlen = tmp-name;
		}
		vlen = end-value;

		value = suhosin_encrypt_single_cookie(name, nlen, value, vlen, (char *)&cryptkey TSRMLS_CC);
		vlen = strlen(value);

		len = sizeof("Set-Cookie: ")-1 + nlen + 1 + vlen + rend-end;
		tmp = emalloc(len + 1);
		tlen = sprintf(tmp, "Set-Cookie: %.*s=%s", nlen,name, value);
		memcpy(tmp + tlen, end, rend-end);
		tmp[len] = 0;

		efree(sapi_header->header);
		efree(value);
		efree(start);

		sapi_header->header = tmp;
		sapi_header->header_len = len;
	}

suhosin_skip_header_handling:
	/* If existing call the sapi header handler */
	if (orig_header_handler) {
		retval = orig_header_handler(sapi_header, op, sapi_headers TSRMLS_CC);
	}

	return retval;
}
/* }}} */


/* {{{ suhosin_hook_header_handler
 */
void suhosin_hook_header_handler()
{
	if (orig_header_handler == NULL) {
		orig_header_handler = sapi_module.header_handler;
		sapi_module.header_handler = suhosin_header_handler;
	}
}
/* }}} */

/* {{{ suhosin_unhook_header_handler
 */
void suhosin_unhook_header_handler()
{
	sapi_module.header_handler = orig_header_handler;
	orig_header_handler = NULL;
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
