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
#include <errno.h>
#ifdef PHP_WIN32
# include "win32/winutil.h"
#endif
#include <fcntl.h>
#ifndef PHP_WIN32
# include <unistd.h>
#endif

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

/*
 * Encrypted value format, version 2 (before the base64 step):
 *
 *   0x02 | IV (16) | AES-256-CBC(IPv4 (4) | length (4, LE) | value | zero padding) | tag (32)
 *
 * tag = HMAC-SHA256(mac key, 0x02 | name length (4, LE) | name | IV | ciphertext). The tag is
 * checked in constant time before anything is decrypted. The encryption and MAC keys are derived
 * from the key suhosin_generate_key() returns. Version 1 values (no IV, an unkeyed checksum)
 * fail the length check and are rejected.
 */
#define SUHOSIN_CRYPT_VERSION 0x02
#define SUHOSIN_CRYPT_IV_LEN 16
#define SUHOSIN_CRYPT_TAG_LEN 32
#define SUHOSIN_CRYPT_HDR_LEN 8
#define SUHOSIN_CRYPT_OVERHEAD (1 + SUHOSIN_CRYPT_IV_LEN + SUHOSIN_CRYPT_TAG_LEN)
/* keeps every length below, and the base64 output, inside an int */
#define SUHOSIN_CRYPT_MAX_LEN ((INT_MAX / 4) * 3 - 256)

static void suhosin_hmac_sha256(const unsigned char *key, int key_len,
                                const unsigned char *d1, int l1, const unsigned char *d2, int l2,
                                const unsigned char *d3, int l3, unsigned char out[32])
{
    suhosin_SHA256_CTX ctx;
    unsigned char k[64], pad[64];
    int i;

    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        suhosin_SHA256Init(&ctx);
        suhosin_SHA256Update(&ctx, key, key_len);
        suhosin_SHA256Final(k, &ctx);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    suhosin_SHA256Init(&ctx);
    suhosin_SHA256Update(&ctx, pad, 64);
    if (l1 > 0) suhosin_SHA256Update(&ctx, d1, l1);
    if (l2 > 0) suhosin_SHA256Update(&ctx, d2, l2);
    if (l3 > 0) suhosin_SHA256Update(&ctx, d3, l3);
    suhosin_SHA256Final(out, &ctx);

    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    suhosin_SHA256Init(&ctx);
    suhosin_SHA256Update(&ctx, pad, 64);
    suhosin_SHA256Update(&ctx, out, 32);
    suhosin_SHA256Final(out, &ctx);

    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
}

/* derive the AES key and the MAC key from the key suhosin_generate_key() returns */
static void suhosin_crypt_keys(const char *key, unsigned char enc_key[32], unsigned char mac_key[32])
{
    suhosin_hmac_sha256((const unsigned char *)key, 32, (const unsigned char *)"suhosin-v2-enc", 14, NULL, 0, NULL, 0, enc_key);
    suhosin_hmac_sha256((const unsigned char *)key, 32, (const unsigned char *)"suhosin-v2-mac", 14, NULL, 0, NULL, 0, mac_key);
}

/* tag over version, name and IV | ciphertext (iv_ct, iv_ct_len bytes) */
static void suhosin_crypt_tag(const unsigned char mac_key[32], const char *var, int vlen,
                              const unsigned char *iv_ct, int iv_ct_len, unsigned char tag[32])
{
    unsigned char hdr[5];

    hdr[0] = SUHOSIN_CRYPT_VERSION;
    hdr[1] = vlen & 0xff;
    hdr[2] = (vlen >> 8) & 0xff;
    hdr[3] = (vlen >> 16) & 0xff;
    hdr[4] = (vlen >> 24) & 0xff;
    suhosin_hmac_sha256(mac_key, 32, hdr, sizeof(hdr), (const unsigned char *)var, vlen, iv_ct, iv_ct_len, tag);
}

/* fill buf with len bytes from the system CSPRNG; SUCCESS or FAILURE */
static int suhosin_random_bytes(unsigned char *buf, size_t len)
{
#ifdef PHP_WIN32
    return php_win32_get_random_bytes(buf, len);
#else
    size_t got = 0;
    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0) {
        return FAILURE;
    }
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            close(fd);
            return FAILURE;
        }
        got += (size_t) n;
    }
    close(fd);
    return SUCCESS;
#endif
}

/* encrypts len bytes of str for the name var; NULL when no random IV can be had or str is too long */
char *suhosin_encrypt_string(char *str, int len, char *var, int vlen, char *key TSRMLS_DC)
{
    int padded_len, total_len, i, slen;
    unsigned char *crypted, *iv, *ct, *tmp;
    unsigned char enc_key[32], mac_key[32];

    if (str == NULL) {
        return NULL;
    }
    /* an empty value is encrypted too: an empty input never passes suhosin_decrypt_string() */
    if (len < 0 || len > SUHOSIN_CRYPT_MAX_LEN) {
        suhosin_log(S_MISC, "value too long to encrypt (%d bytes)", len);
        return NULL;
    }

    padded_len = (SUHOSIN_CRYPT_HDR_LEN + len + 15) & ~0xF;
    total_len = SUHOSIN_CRYPT_OVERHEAD + padded_len;
    crypted = ecalloc(1, total_len + 1);
    iv = crypted + 1;
    ct = iv + SUHOSIN_CRYPT_IV_LEN;

    crypted[0] = SUHOSIN_CRYPT_VERSION;
    if (suhosin_random_bytes(iv, SUHOSIN_CRYPT_IV_LEN) != SUCCESS) {
        efree(crypted);
        suhosin_log(S_MISC, "cannot read random bytes for an encryption IV - value not encrypted");
        return NULL;
    }

    /* plaintext: IPv4 | length | value | zero padding */
    suhosin_get_ipv4((char *)ct TSRMLS_CC);
    ct[4] = len & 0xff;
    ct[5] = (len >> 8) & 0xff;
    ct[6] = (len >> 16) & 0xff;
    ct[7] = (len >> 24) & 0xff;
    memcpy(ct + SUHOSIN_CRYPT_HDR_LEN, str, len);

    suhosin_crypt_keys(key, enc_key, mac_key);
    suhosin_aes_gkey(4, 8, (char *)enc_key TSRMLS_CC);

    /* CBC */
    for (i = 0, tmp = ct; i < padded_len; i += 16, tmp += 16) {
        int j;
        unsigned char *prev = (i == 0) ? iv : tmp - 16;
        for (j = 0; j < 16; j++) tmp[j] ^= prev[j];
        suhosin_aes_encrypt((char *)tmp TSRMLS_CC);
    }

    suhosin_crypt_tag(mac_key, var, vlen, iv, SUHOSIN_CRYPT_IV_LEN + padded_len, ct + padded_len);
    memset(enc_key, 0, sizeof(enc_key));
    memset(mac_key, 0, sizeof(mac_key));

    tmp = php_base64_encode(crypted, total_len, NULL);
    efree(crypted);
    slen = strlen((char *)tmp);
    for (i = 0; i < slen; i++) {
        switch (tmp[i]) {
        case '/': tmp[i] = '-'; break;
        case '=': tmp[i] = '.'; break;
        case '+': tmp[i] = '_'; break;
        }
    }
    return (char *)tmp;
}

/* decrypts and verifies str (changed in place by the base64 alphabet swap); NULL on any failure */
char *suhosin_decrypt_string(char *str, int padded_len, char *var, int vlen, char *key, int *orig_len, int check_ra TSRMLS_DC)
{
    int len, i, ct_len, invalid;
    unsigned int o_len;
    unsigned char *decrypted, *iv, *ct, *tmp;
    unsigned char enc_key[32], mac_key[32], tag[32];
    char buf[4];

    if (orig_len) {
        *orig_len = 0;
    }
    if (str == NULL) {
        return NULL;
    }

    for (i = 0; i < padded_len; i++) {
        switch (str[i]) {
        case '-': str[i] = '/'; break;
        case '.': str[i] = '='; break;
        case '_': str[i] = '+'; break;
        }
    }

    decrypted = php_base64_decode((unsigned char *)str, padded_len, &len);
    if (decrypted == NULL) {
        return NULL;
    }
    ct_len = len - SUHOSIN_CRYPT_OVERHEAD;
    if (len < SUHOSIN_CRYPT_OVERHEAD + 16 || (ct_len % 16) != 0 || decrypted[0] != SUHOSIN_CRYPT_VERSION) {
        goto error_out;
    }
    iv = decrypted + 1;
    ct = iv + SUHOSIN_CRYPT_IV_LEN;

    suhosin_crypt_keys(key, enc_key, mac_key);
    suhosin_crypt_tag(mac_key, var, vlen, iv, SUHOSIN_CRYPT_IV_LEN + ct_len, tag);
    invalid = 0;
    for (i = 0; i < SUHOSIN_CRYPT_TAG_LEN; i++) {
        invalid |= tag[i] ^ ct[ct_len + i];
    }
    memset(mac_key, 0, sizeof(mac_key));
    if (invalid) {
        memset(enc_key, 0, sizeof(enc_key));
        goto error_out;
    }

    suhosin_aes_gkey(4, 8, (char *)enc_key TSRMLS_CC);
    memset(enc_key, 0, sizeof(enc_key));

    /* CBC, last block first, so that each block still has its ciphertext predecessor */
    for (i = ct_len - 16, tmp = ct + i; i >= 0; i -= 16, tmp -= 16) {
        int j;
        unsigned char *prev = (i == 0) ? iv : tmp - 16;
        suhosin_aes_decrypt((char *)tmp TSRMLS_CC);
        for (j = 0; j < 16; j++) tmp[j] ^= prev[j];
    }

    o_len = (unsigned int) ct[4] | ((unsigned int) ct[5] << 8) | ((unsigned int) ct[6] << 16) | ((unsigned int) ct[7] << 24);
    if (o_len > (unsigned int) (ct_len - SUHOSIN_CRYPT_HDR_LEN)) {
        goto error_out;
    }

    /* check IP */
    if (check_ra > 0) {
        if (check_ra > 4) {
            check_ra = 4;
        }
        suhosin_get_ipv4(&buf[0] TSRMLS_CC);
        if (memcmp(buf, ct, check_ra) != 0) {
            goto error_out;
        }
    }

    if (orig_len) {
        *orig_len = (int) o_len;
    }
    memmove(decrypted, ct + SUHOSIN_CRYPT_HDR_LEN, o_len);
    decrypted[o_len] = 0;
    return (char *)decrypted;

error_out:
    efree(decrypted);
    return NULL;
}

/* An empty key used to fall back to a built-in constant that anyone can derive the key from.
   Encryption is now off while the key is empty; this says so once per process and kind. */
int suhosin_crypt_key_set(const char *key, const char *which TSRMLS_DC)
{
    static int warned_cookie = 0, warned_session = 0;
    int *warned;

    if (key != NULL && *key != 0) {
        return 1;
    }
    warned = (which[0] == 'c') ? &warned_cookie : &warned_session;
    if (!*warned) {
        *warned = 1;
        suhosin_log(S_MISC, "suhosin.%s.encrypt is on but suhosin.%s.cryptkey is empty - %s encryption is disabled until a key is set", which, which, which);
    }
    return 0;
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
    /* callers check suhosin_crypt_key_set() first: there is no built-in default key */
    if (key != NULL) {
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
