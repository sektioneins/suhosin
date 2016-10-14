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
  | Author: David Carlier <devnexen@gmail.com>                           |
  +----------------------------------------------------------------------+
*/

#if defined(__OpenBSD__) && defined(SUHOSIN_EXPERIMENTAL)

#include <unistd.h>
#include <errno.h>
#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_smart_str.h"

#include "pledge.h"

const char *promises_defined[] = {
    "rpath",
    "wpath",
    "cpath",
    "tmppath",
    "inet",
    "flock",
    "unix",
    "dns",
    "sendfd",
    "recvfd",
    "proc",
    "exec",
    NULL
};

/* {{{ proto string pledge(string str [, bool raw_output])
   Wrapper around pledge call. Hence subsequent calls are
   allowed only to diminish the permissions. */
static PHP_FUNCTION(suhosin_pledge)
{
    zval *promises, **current;
    HashTable *hashp;
    HashPosition hashpos;
    const char *pm;
    int ret;
    smart_str promisesbuf = { 0 };

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &promises) == FAILURE) {
        return;
    }

    /* PHP needs at least few functions from this promise */
    smart_str_appends(&promisesbuf, "stdio");
    hashp = Z_ARRVAL_P(promises);
    for (zend_hash_internal_pointer_reset_ex(hashp, &hashpos);
         zend_hash_get_current_data_ex(hashp, (void **)&current, &hashpos) == SUCCESS;
         zend_hash_move_forward_ex(hashp, &hashpos)) {
        if (Z_TYPE_PP(current) != IS_STRING)
            continue;
        pm = NULL;
        const char **ptr = promises_defined;
        char *pp = Z_STRVAL_PP(current);
        char *p = php_trim(pp, strlen(pp), " ", 1, NULL, 3);
        while (*ptr) {
            if (strcmp(*ptr, p) == 0) {
                pm = *ptr;
                break;
            }
            ptr ++;
        }
        if (pm == NULL) {
            if (strcmp(p, "stdio") != 0)
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "pledge: %s invalid or forbidden promise", p);
            efree(p);
            continue;
        }
        efree(p);
        smart_str_appends(&promisesbuf, " ");
        smart_str_appends(&promisesbuf, pm);
    }

    smart_str_0(&promisesbuf);
    ret = pledge(promisesbuf.c, NULL);
    smart_str_free(&promisesbuf);

    if (ret == -1)
        php_error_docref(NULL TSRMLS_CC, E_ERROR, "pledge failed: %s", strerror(errno));

    RETVAL_LONG(ret);
}

/* }}} */

/* {{{ suhosin_pledge_functions[]
 */
static zend_function_entry suhosin_pledge_functions[] = {
	PHP_NAMED_FE(pledge, PHP_FN(suhosin_pledge), NULL)
	{NULL, NULL, NULL}
};
/* }}} */

void suhosin_hook_pledge(TSRMLS_D)
{
    zend_register_functions(NULL, suhosin_pledge_functions, NULL, MODULE_PERSISTENT TSRMLS_CC);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
#endif
