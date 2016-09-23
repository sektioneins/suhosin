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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "TSRM.h"
#include "php_suhosin.h"
#include "ext/standard/base64.h"
#include "sha256.h"

static void suhosin_get_ipv4(char *buf TSRMLS_DC)
{
    char *raddr = suhosin_getenv(ZEND_STRL("REMOTE_ADDR") TSRMLS_CC);
    int i;


    if (raddr == NULL) {
        memset(buf, 0, 4);
        return;
    }

    for (i=0; i<4; i++) {
        if (raddr[0] == 0) {
            buf[i] = 0;
        } else {
            buf[i] = strtol(raddr, &raddr, 10);
            if (raddr[0] == '.') {
                raddr++;
            }
        }
    }
}

char *suhosin_encrypt_string(char *str, int len, char *var, int vlen, char *key TSRMLS_DC)
{
    int padded_len, i, slen;
    unsigned char *crypted, *tmp;
    unsigned int check = 0x13579BDF;

    if (str == NULL) {
    return NULL;
    }
    if (len == 0) {
        return estrndup("", 0);
    }


    suhosin_aes_gkey(4,8,key TSRMLS_CC);

    padded_len = ((len+15) & ~0xF);
    crypted = emalloc(16+padded_len+1);
    memset(crypted, 0xff, 16+padded_len+1);
    memcpy(crypted+16, str, len+1);

    /* calculate check value */
    for (i = 0; i<vlen; i++) {
        check = (check << 3) | (check >> (32-3));
        check += check << 1;
        check ^= (unsigned char)var[i];
    }
    for (i = 0; i<len; i++) {
        check = (check << 3) | (check >> (32-3));
        check += check << 1;
        check ^= (unsigned char)str[i];
    }

    /* store ip value */
    suhosin_get_ipv4((char *)crypted+4 TSRMLS_CC);

    /* store check value */
    crypted[8] = check & 0xff;
    crypted[9] = (check >> 8) & 0xff;
    crypted[10] = (check >> 16) & 0xff;
    crypted[11] = (check >> 24) & 0xff;

    /* store original length */
    crypted[12] = len & 0xff;
    crypted[13] = (len >> 8) & 0xff;
    crypted[14] = (len >> 16) & 0xff;
    crypted[15] = (len >> 24) & 0xff;

    for (i=0, tmp=crypted; i<padded_len+16; i+=16, tmp+=16) {
        if (i > 0) {
            int j;
            for (j=0; j<16; j++) tmp[j] ^= tmp[j-16];
        }
        suhosin_aes_encrypt((char *)tmp TSRMLS_CC);
    }

    tmp = php_base64_encode(crypted, padded_len+16, NULL);
    efree(crypted);
    slen=strlen((char *)tmp);
    for (i=0; i<slen; i++) {
        switch (tmp[i]) {
        case '/': tmp[i]='-'; break;
        case '=': tmp[i]='.'; break;
        case '+': tmp[i]='_'; break;
        }
    }
    return (char *)tmp;
}

char *suhosin_decrypt_string(char *str, int padded_len, char *var, int vlen, char *key, int *orig_len, int check_ra TSRMLS_DC)
{
    int len, i, o_len, invalid = 0;
    unsigned char *decrypted, *tmp;
    unsigned int check = 0x13579BDF;
    char buf[4];

    if (str == NULL) {
    return NULL;
    }

    if (padded_len == 0) {
        if (orig_len) {
            *orig_len = 0;
        }
        return estrndup("", 0);
    }
    suhosin_aes_gkey(4,8,key TSRMLS_CC);

    for (i=0; i<padded_len; i++) {
        switch (str[i]) {
        case '-': str[i]='/'; break;
        case '.': str[i]='='; break;
        case '_': str[i]='+'; break;
        }
    }

    decrypted = php_base64_decode((unsigned char *)str, padded_len, &len);
    if (decrypted == NULL || len < 2*16 || (len % 16) != 0) {
error_out:
        if (decrypted != NULL) {
            efree(decrypted);
        }
        if (orig_len) {
            *orig_len = 0;
        }
        return NULL;
    }

    for (i=len-16, tmp=decrypted+i; i>=0; i-=16, tmp-=16) {
    suhosin_aes_decrypt((char *)tmp TSRMLS_CC);
    if (i > 0) {
        int j;
        for (j=0; j<16; j++) tmp[j] ^= tmp[j-16];
    }
    }

    /* retrieve orig_len */
    o_len = decrypted[15];
    o_len <<= 8;
    o_len |= decrypted[14];
    o_len <<= 8;
    o_len |= decrypted[13];
    o_len <<= 8;
    o_len |= decrypted[12];

    if (o_len < 0 || o_len > len-16) {
        goto error_out;
    }

    /* calculate check value */
    for (i = 0; i<vlen; i++) {
        check = (check << 3) | (check >> (32-3));
        check += check << 1;
        check ^= (unsigned char)var[i];
    }
    for (i = 0; i<o_len; i++) {
        check = (check << 3) | (check >> (32-3));
        check += check << 1;
        check ^= decrypted[16+i];
    }

    /* check value */
    invalid = (decrypted[8] != (check & 0xff)) ||
           (decrypted[9] != ((check >> 8) & 0xff)) ||
               (decrypted[10] != ((check >> 16) & 0xff)) ||
               (decrypted[11] != ((check >> 24) & 0xff));

    /* check IP */
    if (check_ra > 0) {
        if (check_ra > 4) {
            check_ra = 4;
        }
        suhosin_get_ipv4(&buf[0] TSRMLS_CC);
        if (memcmp(buf, decrypted+4, check_ra) != 0) {
            goto error_out;
        }
    }

    if (invalid) {
        goto error_out;
    }

    if (orig_len) {
        *orig_len = o_len;
    }

    memmove(decrypted, decrypted+16, o_len);
    decrypted[o_len] = 0;
    /* we do not realloc() here because 16 byte less
       is simply not worth the overhead */
    return (char *)decrypted;
}

char *suhosin_generate_key(char *key, zend_bool ua, zend_bool dr, long raddr, char *cryptkey TSRMLS_DC)
{
    char *_ua = NULL;
    char *_dr = NULL;
    char *_ra = NULL;
    suhosin_SHA256_CTX ctx;

    if (ua) {
        _ua = suhosin_getenv(ZEND_STRL("HTTP_USER_AGENT") TSRMLS_CC);
    }

    if (dr) {
        _dr = suhosin_getenv(ZEND_STRL("DOCUMENT_ROOT") TSRMLS_CC);
    }

    if (raddr > 0) {
        _ra = suhosin_getenv(ZEND_STRL("REMOTE_ADDR") TSRMLS_CC);
    }

    SDEBUG("(suhosin_generate_key) KEY: %s - UA: %s - DR: %s - RA: %s", key,_ua,_dr,_ra);

    suhosin_SHA256Init(&ctx);
    if (key == NULL || *key == 0) {
        suhosin_SHA256Update(&ctx, (unsigned char*)"D3F4UL7", strlen("D3F4UL7"));
    } else {
        suhosin_SHA256Update(&ctx, (unsigned char*)key, strlen(key));
    }
    if (_ua) {
        suhosin_SHA256Update(&ctx, (unsigned char*)_ua, strlen(_ua));
    }
    if (_dr) {
        suhosin_SHA256Update(&ctx, (unsigned char*)_dr, strlen(_dr));
    }
    if (_ra) {
        if (raddr >= 4) {
            suhosin_SHA256Update(&ctx, (unsigned char*)_ra, strlen(_ra));
        } else {
            long dots = 0;
            char *tmp = _ra;

            while (*tmp) {
                if (*tmp == '.') {
                    dots++;
                    if (dots == raddr) {
                        break;
                    }
                }
                tmp++;
            }
            suhosin_SHA256Update(&ctx, (unsigned char*)_ra, tmp-_ra);
        }
    }
    suhosin_SHA256Final((unsigned char *)cryptkey, &ctx);
    cryptkey[32] = 0; /* uhmm... not really a string */

    return cryptkey;
}
