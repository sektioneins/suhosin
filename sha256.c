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

/* $Id: sha256.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $ */

#include <stdio.h>
#include "php.h"

/* This code is heavily based on the PHP md5/sha1 implementations */ 

#include "sha256.h"

static void make_sha256_digest(char *sha256str, unsigned char *digest)
{
	int i;

	for (i = 0; i < 32; i++) {
		sprintf(sha256str, "%02x", digest[i]);
		sha256str += 2;
	}

	*sha256str = '\0';
}

/* {{{ proto string sha256(string str [, bool raw_output])
   Calculate the sha256 hash of a string */
static PHP_FUNCTION(suhosin_sha256)
{
	char *arg;
	int arg_len;
	zend_bool raw_output = 0;
	char sha256str[65];
	suhosin_SHA256_CTX context;
	unsigned char digest[32];
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|b", &arg, &arg_len, &raw_output) == FAILURE) {
		return;
	}

	sha256str[0] = '\0';
	suhosin_SHA256Init(&context);
	suhosin_SHA256Update(&context, (unsigned char *)arg, (unsigned int)arg_len);
	suhosin_SHA256Final(digest, &context);
	if (raw_output) {
		RETURN_STRINGL((char *)digest, 32, 1);
	} else {
		make_sha256_digest(sha256str, digest);
		RETVAL_STRING(sha256str, 1);
	}

}

/* }}} */

/* {{{ proto string sha256_file(string filename [, bool raw_output])
   Calculate the sha256 hash of given filename */
static PHP_FUNCTION(suhosin_sha256_file)
{
	char          *arg;
	int           arg_len;
	zend_bool raw_output = 0;
	char          sha256str[65];
	unsigned char buf[1024];
	unsigned char digest[32];
	suhosin_SHA256_CTX   context;
	int           n;
	FILE          *fp;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|b", &arg, &arg_len, &raw_output) == FAILURE) {
		return;
	}

	if (php_check_open_basedir(arg TSRMLS_CC)) {
		RETURN_FALSE;
	}

	if ((fp = VCWD_FOPEN(arg, "rb")) == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unable to open file");
		RETURN_FALSE;
	}

	suhosin_SHA256Init(&context);

	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
		suhosin_SHA256Update(&context, buf, n);
	}

	suhosin_SHA256Final(digest, &context);

	if (ferror(fp)) {
		fclose(fp);
		RETURN_FALSE;
	}

	fclose(fp);

	if (raw_output) {
		RETURN_STRINGL((char *)digest, 32, 1);
	} else {
		make_sha256_digest(sha256str, digest);
		RETVAL_STRING(sha256str, 1);
	}
}
/* }}} */


static void SHA256Transform(php_uint32[8], const unsigned char[64]);
static void SHA256Encode(unsigned char *, php_uint32 *, unsigned int);
static void SHA256Decode(php_uint32 *, const unsigned char *, unsigned int);

static unsigned char PADDING[64] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic SHA256 functions.
 */
#define F(x) (ROTATE_RIGHT(x,2) ^ ROTATE_RIGHT(x,13) ^ ROTATE_RIGHT(x,22))
#define G(x, y, z) (((x) & (y)) | ((z) & ((y) | (x))))
#define H(x) (ROTATE_RIGHT(x,6) ^ ROTATE_RIGHT(x,11) ^ ROTATE_RIGHT(x,25))
#define I(x, y, z) (((x) & (y)) | ((~x) & z))

/* ROTATE_RIGHT rotates x right n bits.
 */
#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

/* W[i]
 */
#define W(i) ( tmp1=ROTATE_RIGHT(x[(i-15)&15],7)^ROTATE_RIGHT(x[(i-15)&15],18)^(x[(i-15)&15] >> 3), \
	tmp2=ROTATE_RIGHT(x[(i-2)&15],17)^ROTATE_RIGHT(x[(i-2)&15],19)^(x[(i-2)&15] >> 10), \
	(x[i&15]=x[i&15] + tmp1 + x[(i-7)&15] + tmp2) ) 

/* ROUND function of sha256
 */

#define ROUND(a,b,c,d,e,f,g,h,w,k) { \
 t1 = (h) + H((e)) + I((e), (f), (g)) + (k) + (php_uint32)(w); \
 (h) = F((a)) + G((a), (b), (c)) + t1; \
 (d) += t1; \
 } 
			                    

/* {{{ suhosin_SHA256Init
 * SHA256 initialization. Begins an SHA256 operation, writing a new context.
 */
void suhosin_SHA256Init(suhosin_SHA256_CTX * context)
{
	context->count[0] = context->count[1] = 0;
	/* Load magic initialization constants.
	 */
	context->state[0] = 0x6a09e667;
	context->state[1] = 0xbb67ae85;
	context->state[2] = 0x3c6ef372;
	context->state[3] = 0xa54ff53a;
	context->state[4] = 0x510e527f;
	context->state[5] = 0x9b05688c;
	context->state[6] = 0x1f83d9ab;
	context->state[7] = 0x5be0cd19;	
}
/* }}} */

/* {{{ suhosin_SHA256Update
   SHA256 block update operation. Continues an SHA256 message-digest
   operation, processing another message block, and updating the
   context.
 */
void suhosin_SHA256Update(suhosin_SHA256_CTX * context, const unsigned char *input,
			   unsigned int inputLen)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int) ((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((php_uint32) inputLen << 3))
		< ((php_uint32) inputLen << 3))
		context->count[1]++;
	context->count[1] += ((php_uint32) inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible.
	 */
	if (inputLen >= partLen) {
		memcpy
			((unsigned char*) & context->buffer[index], (unsigned char*) input, partLen);
		SHA256Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			SHA256Transform(context->state, &input[i]);

		index = 0;
	} else
		i = 0;

	/* Buffer remaining input */
	memcpy
		((unsigned char*) & context->buffer[index], (unsigned char*) & input[i],
		 inputLen - i);
}
/* }}} */

/* {{{ suhosin_SHA256Final
   SHA256 finalization. Ends an SHA256 message-digest operation, writing the
   the message digest and zeroizing the context.
 */
void suhosin_SHA256Final(unsigned char digest[32], suhosin_SHA256_CTX * context)
{
	unsigned char bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	bits[7] = context->count[0] & 0xFF;
	bits[6] = (context->count[0] >> 8) & 0xFF;
	bits[5] = (context->count[0] >> 16) & 0xFF;
	bits[4] = (context->count[0] >> 24) & 0xFF;
	bits[3] = context->count[1] & 0xFF;
	bits[2] = (context->count[1] >> 8) & 0xFF;
	bits[1] = (context->count[1] >> 16) & 0xFF;
	bits[0] = (context->count[1] >> 24) & 0xFF;
	
	/* Pad out to 56 mod 64.
	 */
	index = (unsigned int) ((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	suhosin_SHA256Update(context, PADDING, padLen);

	/* Append length (before padding) */
	suhosin_SHA256Update(context, bits, 8);

	/* Store state in digest */
	SHA256Encode(digest, context->state, 32);

	/* Zeroize sensitive information.
	 */
	memset((unsigned char*) context, 0, sizeof(*context));
}
/* }}} */

/* {{{ SHA256Transform
 * SHA256 basic transformation. Transforms state based on block.
 */
static void SHA256Transform(state, block)
php_uint32 state[8];
const unsigned char block[64];
{
	php_uint32 a = state[0], b = state[1], c = state[2];
	php_uint32 d = state[3], e = state[4], f = state[5];
	php_uint32 g = state[6], h = state[7], x[16], tmp1, tmp2, t1;

	SHA256Decode(x, block, 64);

	ROUND(a, b, c, d, e, f, g, h, x[0], 0x428a2f98)
	ROUND(h, a, b, c, d, e, f, g, x[1], 0x71374491)
	ROUND(g, h, a, b, c, d, e, f, x[2], 0xb5c0fbcf)
	ROUND(f, g, h, a, b, c, d, e, x[3], 0xe9b5dba5)
	ROUND(e, f, g, h, a, b, c, d, x[4], 0x3956c25b)
	ROUND(d, e, f, g, h, a, b, c, x[5], 0x59f111f1)
	ROUND(c, d, e, f, g, h, a, b, x[6], 0x923f82a4)
	ROUND(b, c, d, e, f, g, h, a, x[7], 0xab1c5ed5)
	ROUND(a, b, c, d, e, f, g, h, x[8], 0xd807aa98)
	ROUND(h, a, b, c, d, e, f, g, x[9], 0x12835b01)
	ROUND(g, h, a, b, c, d, e, f, x[10], 0x243185be)
	ROUND(f, g, h, a, b, c, d, e, x[11], 0x550c7dc3)
	ROUND(e, f, g, h, a, b, c, d, x[12], 0x72be5d74)
	ROUND(d, e, f, g, h, a, b, c, x[13], 0x80deb1fe)
	ROUND(c, d, e, f, g, h, a, b, x[14], 0x9bdc06a7)
	ROUND(b, c, d, e, f, g, h, a, x[15], 0xc19bf174)
	ROUND(a, b, c, d, e, f, g, h, W(16), 0xe49b69c1)
	ROUND(h, a, b, c, d, e, f, g, W(17), 0xefbe4786)
	ROUND(g, h, a, b, c, d, e, f, W(18), 0x0fc19dc6)
	ROUND(f, g, h, a, b, c, d, e, W(19), 0x240ca1cc)
	ROUND(e, f, g, h, a, b, c, d, W(20), 0x2de92c6f)
	ROUND(d, e, f, g, h, a, b, c, W(21), 0x4a7484aa)
	ROUND(c, d, e, f, g, h, a, b, W(22), 0x5cb0a9dc)
	ROUND(b, c, d, e, f, g, h, a, W(23), 0x76f988da)
	ROUND(a, b, c, d, e, f, g, h, W(24), 0x983e5152)
	ROUND(h, a, b, c, d, e, f, g, W(25), 0xa831c66d)
	ROUND(g, h, a, b, c, d, e, f, W(26), 0xb00327c8)
	ROUND(f, g, h, a, b, c, d, e, W(27), 0xbf597fc7)
	ROUND(e, f, g, h, a, b, c, d, W(28), 0xc6e00bf3)
	ROUND(d, e, f, g, h, a, b, c, W(29), 0xd5a79147)
	ROUND(c, d, e, f, g, h, a, b, W(30), 0x06ca6351)
	ROUND(b, c, d, e, f, g, h, a, W(31), 0x14292967)
	ROUND(a, b, c, d, e, f, g, h, W(32), 0x27b70a85)
	ROUND(h, a, b, c, d, e, f, g, W(33), 0x2e1b2138)
	ROUND(g, h, a, b, c, d, e, f, W(34), 0x4d2c6dfc)
	ROUND(f, g, h, a, b, c, d, e, W(35), 0x53380d13)
	ROUND(e, f, g, h, a, b, c, d, W(36), 0x650a7354)
	ROUND(d, e, f, g, h, a, b, c, W(37), 0x766a0abb)
	ROUND(c, d, e, f, g, h, a, b, W(38), 0x81c2c92e)
	ROUND(b, c, d, e, f, g, h, a, W(39), 0x92722c85)
	ROUND(a, b, c, d, e, f, g, h, W(40), 0xa2bfe8a1)
	ROUND(h, a, b, c, d, e, f, g, W(41), 0xa81a664b)
	ROUND(g, h, a, b, c, d, e, f, W(42), 0xc24b8b70)
	ROUND(f, g, h, a, b, c, d, e, W(43), 0xc76c51a3)
	ROUND(e, f, g, h, a, b, c, d, W(44), 0xd192e819)
	ROUND(d, e, f, g, h, a, b, c, W(45), 0xd6990624)
	ROUND(c, d, e, f, g, h, a, b, W(46), 0xf40e3585)
	ROUND(b, c, d, e, f, g, h, a, W(47), 0x106aa070)
	ROUND(a, b, c, d, e, f, g, h, W(48), 0x19a4c116)
	ROUND(h, a, b, c, d, e, f, g, W(49), 0x1e376c08)
	ROUND(g, h, a, b, c, d, e, f, W(50), 0x2748774c)
	ROUND(f, g, h, a, b, c, d, e, W(51), 0x34b0bcb5)
	ROUND(e, f, g, h, a, b, c, d, W(52), 0x391c0cb3)
	ROUND(d, e, f, g, h, a, b, c, W(53), 0x4ed8aa4a)
	ROUND(c, d, e, f, g, h, a, b, W(54), 0x5b9cca4f)
	ROUND(b, c, d, e, f, g, h, a, W(55), 0x682e6ff3)
	ROUND(a, b, c, d, e, f, g, h, W(56), 0x748f82ee)
	ROUND(h, a, b, c, d, e, f, g, W(57), 0x78a5636f)
	ROUND(g, h, a, b, c, d, e, f, W(58), 0x84c87814)
	ROUND(f, g, h, a, b, c, d, e, W(59), 0x8cc70208)
	ROUND(e, f, g, h, a, b, c, d, W(60), 0x90befffa)
	ROUND(d, e, f, g, h, a, b, c, W(61), 0xa4506ceb)
	ROUND(c, d, e, f, g, h, a, b, W(62), 0xbef9a3f7)
	ROUND(b, c, d, e, f, g, h, a, W(63), 0xc67178f2)

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;

	/* Zeroize sensitive information. */
	memset((unsigned char*) x, 0, sizeof(x));
}
/* }}} */

/* {{{ SHA256Encode
   Encodes input (php_uint32) into output (unsigned char). Assumes len is
   a multiple of 4.
 */
static void SHA256Encode(output, input, len)
unsigned char *output;
php_uint32 *input;
unsigned int len;
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char) ((input[i] >> 24) & 0xff);
		output[j + 1] = (unsigned char) ((input[i] >> 16) & 0xff);
		output[j + 2] = (unsigned char) ((input[i] >> 8) & 0xff);
		output[j + 3] = (unsigned char) (input[i] & 0xff);
	}
}
/* }}} */

/* {{{ SHA256Decode
   Decodes input (unsigned char) into output (php_uint32). Assumes len is
   a multiple of 4.
 */
static void SHA256Decode(output, input, len)
php_uint32 *output;
const unsigned char *input;
unsigned int len;
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((php_uint32) input[j + 3]) | (((php_uint32) input[j + 2]) << 8) |
			(((php_uint32) input[j + 1]) << 16) | (((php_uint32) input[j]) << 24);
}
/* }}} */


/* {{{ suhosin_sha256_functions[]
 */
static zend_function_entry suhosin_sha256_functions[] = {
	PHP_NAMED_FE(sha256, PHP_FN(suhosin_sha256), NULL)
	PHP_NAMED_FE(sha256_file, PHP_FN(suhosin_sha256_file), NULL)
	{NULL, NULL, NULL}
};
/* }}} */


void suhosin_hook_sha256(TSRMLS_D)
{
	/* check if we already have sha256 support */
	if (zend_hash_exists(CG(function_table), "sha256", sizeof("sha256"))) {
		return;		
	}
	
	/* add the sha256 functions */
	zend_register_functions(NULL, suhosin_sha256_functions, NULL, MODULE_PERSISTENT TSRMLS_CC);
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
