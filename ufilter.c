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
  $Id: ufilter.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_suhosin.h"
#include "php_variables.h"
#include "suhosin_rfc1867.h"
#include "ext/standard/php_var.h"

#if !HAVE_RFC1867_CALLBACK
PHP_SUHOSIN_API int (*php_rfc1867_callback)(unsigned int event, void *event_data, void **extra TSRMLS_DC) = NULL;
#endif


/* {{{ SAPI_UPLOAD_VARNAME_FILTER_FUNC
 */
static int check_fileupload_varname(char *varname TSRMLS_DC)
{
	char *index, *prev_index = NULL, *var;
	unsigned int var_len, total_len, depth = 0;

	var = estrdup(varname);

	/* Normalize the variable name */
	normalize_varname(var);

	/* Find length of variable name */
	index = strchr(var, '[');
	total_len = strlen(var);
	var_len = index ? index-var : total_len;

	/* Drop this variable if it exceeds the varname/total length limit */
	if (SUHOSIN_G(max_varname_length) && SUHOSIN_G(max_varname_length) < var_len) {
		suhosin_log(S_FILES, "configured request variable name length limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN_G(simulation)) {
			goto return_failure;
		}
	}
	if (SUHOSIN_G(max_totalname_length) && SUHOSIN_G(max_totalname_length) < total_len) {
		suhosin_log(S_FILES, "configured request variable total name length limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN_G(simulation)) {
			goto return_failure;
		}
	}
	if (SUHOSIN_G(max_post_name_length) && SUHOSIN_G(max_post_name_length) < var_len) {
		suhosin_log(S_FILES, "configured POST variable name length limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN_G(simulation)) {
			goto return_failure;
		}
	}
	if (SUHOSIN_G(max_post_totalname_length) && SUHOSIN_G(max_post_totalname_length) < var_len) {
		suhosin_log(S_FILES, "configured POST variable total name length limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN_G(simulation)) {
			goto return_failure;
		}
	}

	/* Find out array depth */
	while (index) {
		char *index_end;
		unsigned int index_length;

		/* overjump '[' */
		index++;

		/* increase array depth */
		depth++;

		index_end = strchr(index, ']');
		if (index_end == NULL) {
			index_end = index+strlen(index);
		}

		index_length = index_end - index;

		if (SUHOSIN_G(max_array_index_length) && SUHOSIN_G(max_array_index_length) < index_length) {
			suhosin_log(S_FILES, "configured request variable array index length limit exceeded - dropped variable '%s'", var);
			if (!SUHOSIN_G(simulation)) {
				goto return_failure;
			}
		}
		if (SUHOSIN_G(max_post_array_index_length) && SUHOSIN_G(max_post_array_index_length) < index_length) {
			suhosin_log(S_FILES, "configured POST variable array index length limit exceeded - dropped variable '%s'", var);
			if (!SUHOSIN_G(simulation)) {
				goto return_failure;
			}
		}

		/* index whitelist/blacklist */
		if (SUHOSIN_G(array_index_whitelist) && *(SUHOSIN_G(array_index_whitelist))) {
			if (suhosin_strnspn(index, index_length, SUHOSIN_G(array_index_whitelist)) != index_length) {
				suhosin_log(S_VARS, "array index contains not whitelisted characters - dropped variable '%s'", var);
				if (!SUHOSIN_G(simulation)) {
					goto return_failure;
				}
			}
		} else if (SUHOSIN_G(array_index_blacklist) && *(SUHOSIN_G(array_index_blacklist))) {
			if (suhosin_strncspn(index, index_length, SUHOSIN_G(array_index_blacklist)) != index_length) {
				suhosin_log(S_VARS, "array index contains blacklisted characters - dropped variable '%s'", var);
				if (!SUHOSIN_G(simulation)) {
					goto return_failure;
				}
			}
		}


		index = strchr(index, '[');
	}

	/* Drop this variable if it exceeds the array depth limit */
	if (SUHOSIN_G(max_array_depth) && SUHOSIN_G(max_array_depth) < depth) {
		suhosin_log(S_FILES, "configured request variable array depth limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN_G(simulation)) {
			goto return_failure;
		}
	}
	if (SUHOSIN_G(max_post_array_depth) && SUHOSIN_G(max_post_array_depth) < depth) {
		suhosin_log(S_FILES, "configured POST variable array depth limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN_G(simulation)) {
			goto return_failure;
		}
	}


	/* Drop this variable if it is one of GLOBALS, _GET, _POST, ... */
	/* This is to protect several silly scripts that do globalizing themself */
	if (php_varname_check(var, var_len, 1 TSRMLS_CC) == FAILURE || suhosin_is_protected_varname(var, var_len)) {
		suhosin_log(S_FILES, "tried to register forbidden variable '%s' through FILE variables", var);
		if (!SUHOSIN_G(simulation)) {
			goto return_failure;
		}
	}

	efree(var);
	return SUCCESS;

return_failure:
	efree(var);
	return FAILURE;
}
/* }}} */

#ifdef SUHOSIN_EXPERIMENTAL
static inline int suhosin_validate_utf8_multibyte(const char* cp, size_t maxlen)
{
	if (maxlen < 2 || !(*cp & 0x80)) { return 0; }
	if ((*cp & 0xe0) == 0xc0 &&					// 1st byte is 110xxxxx
		(*(cp+1) & 0xc0) == 0x80 &&				// 2nd byte is 10xxxxxx
		(*cp & 0x1e)) {							// overlong check 110[xxxx]x 10xxxxxx
			 return 2;
	}
	if (maxlen < 3) { return 0; }
	if ((*cp & 0xf0) == 0xe0 &&					// 1st byte is 1110xxxx
		(*(cp+1) & 0xc0) == 0x80 &&				// 2nd byte is 10xxxxxx
		(*(cp+2) & 0xc0) == 0x80 &&				// 3rd byte is 10xxxxxx
		((*cp & 0x0f) | (*(cp+1) & 0x20))) {	// 1110[xxxx] 10[x]xxxxx 10xxxxxx
			return 3;
	}
	if (maxlen < 4) { return 0; }
	if ((*cp & 0xf8) == 0xf0 &&				// 1st byte is 11110xxx
		(*(cp+1) & 0xc0) == 0x80 &&				// 2nd byte is 10xxxxxx
		(*(cp+2) & 0xc0) == 0x80 &&				// 3rd byte is 10xxxxxx
		(*(cp+3) & 0xc0) == 0x80 &&				// 4th byte is 10xxxxxx
		((*cp & 0x07) | (*(cp+1) & 0x30))) {	// 11110[xxx] 10[xx]xxxx 10xxxxxx 10xxxxxx
			return 4;
	}
	return 0;
}
#endif

int suhosin_rfc1867_filter(unsigned int event, void *event_data, void **extra TSRMLS_DC)
{
	int retval = SUCCESS;

	SDEBUG("rfc1867_filter %u", event);

	switch (event) {
		case MULTIPART_EVENT_START:
		case MULTIPART_EVENT_FORMDATA:
			/* nothing todo */
			break;

		case MULTIPART_EVENT_FILE_START:
			{
				multipart_event_file_start *mefs = (multipart_event_file_start *) event_data;

				/* Drop if no more variables flag is set */
				if (SUHOSIN_G(no_more_uploads)) {
						goto continue_with_failure;
				}

				/* Drop this fileupload if the limit is reached */
		  		if (SUHOSIN_G(upload_limit) && SUHOSIN_G(upload_limit) <= SUHOSIN_G(num_uploads)) {
			  		suhosin_log(S_FILES, "configured fileupload limit exceeded - file dropped");
			  		if (!SUHOSIN_G(simulation)) {
						SUHOSIN_G(no_more_uploads) = 1;
						goto continue_with_failure;
			  		}
		  		}


				if (check_fileupload_varname(mefs->name TSRMLS_CC) == FAILURE) {
					goto continue_with_failure;
				}
			}

			break;

		case MULTIPART_EVENT_FILE_DATA:

			if (SUHOSIN_G(upload_disallow_elf)) {
				multipart_event_file_data *mefd = (multipart_event_file_data *) event_data;

				if (mefd->offset == 0 && mefd->length > 10) {
					if (mefd->data[0] == 0x7F && mefd->data[1] == 'E' && mefd->data[2] == 'L' && mefd->data[3] == 'F') {
						suhosin_log(S_FILES, "uploaded file is an ELF executable - file dropped");
						if (!SUHOSIN_G(simulation)) {
							goto continue_with_failure;
						}
					}
				}
			}

			if (SUHOSIN_G(upload_disallow_binary)) {

				multipart_event_file_data *mefd = (multipart_event_file_data *) event_data;

				char *cp, *cpend;
				int n;
				cpend = mefd->data + mefd->length;
				for (cp = mefd->data; cp < cpend; cp++) {
					if (*cp >= 32 || isspace(*cp)) {
						continue;
					}
#ifdef SUHOSIN_EXPERIMENTAL
					if ((*cp & 0x80) && SUHOSIN_G(upload_allow_utf8)) {
						SDEBUG("checking char %x", *cp);
						if ((n = suhosin_validate_utf8_multibyte(cp, cpend-cp))) { // valid UTF8 multibyte character
							cp += n - 1;
							continue;
						}
					}
#endif
					suhosin_log(S_FILES, "uploaded file contains binary data - file dropped");
					if (!SUHOSIN_G(simulation)) {
						goto continue_with_failure;
					}
					break;
				}
			}

			if (SUHOSIN_G(upload_remove_binary)) {

				multipart_event_file_data *mefd = (multipart_event_file_data *) event_data;
				size_t i, j;
				int n;

				for (i=0, j=0; i<mefd->length; i++) {
					if (mefd->data[i] >= 32 || isspace(mefd->data[i])) {
						mefd->data[j++] = mefd->data[i];
					}
#ifdef SUHOSIN_EXPERIMENTAL
					else if (SUHOSIN_G(upload_allow_utf8) && mefd->data[i] & 0x80) {
						n = suhosin_validate_utf8_multibyte(mefd->data + i, mefd->length - i);
						if (!n) { continue; }
						while (n--) {
							mefd->data[j++] = mefd->data[i++];
						}
						i--;
					}
#endif
				}
				mefd->data[j] = '\0';

				SDEBUG("removing binary %zu %zu",i,j);
				/* IMPORTANT FOR DAISY CHAINING */
				mefd->length = j;
				if (mefd->newlength) {
					*mefd->newlength = j;
				}
			}

			break;

		case MULTIPART_EVENT_FILE_END:

			if (SUHOSIN_G(upload_verification_script)) {
				multipart_event_file_end *mefe = (multipart_event_file_end *) event_data;
				char cmd[8192];
				FILE *in;
				int first=1;
				struct stat st;
				char *sname = SUHOSIN_G(upload_verification_script);

				/* ignore files that will get deleted anyway */
				if (mefe->cancel_upload) {
					break;
				}

				/* ignore empty scriptnames */
				while (isspace(*sname)) ++sname;
				if (*sname == 0) {
					SUHOSIN_G(num_uploads)++;
					break;
				}

				if (VCWD_STAT(sname, &st) < 0) {
					suhosin_log(S_FILES, "unable to find fileupload verification script %s - file dropped", sname);
					if (!SUHOSIN_G(simulation)) {
						goto continue_with_failure;
					} else {
						goto continue_with_next;
					}
				}
				if (access(sname, X_OK|R_OK) < 0) {
					suhosin_log(S_FILES, "fileupload verification script %s is not executable - file dropped", sname);
					if (!SUHOSIN_G(simulation)) {
						goto continue_with_failure;
					} else {
						goto continue_with_next;
					}
				}

				ap_php_snprintf(cmd, sizeof(cmd), "%s %s 2>&1", sname, mefe->temp_filename);

				if ((in=VCWD_POPEN(cmd, "r"))==NULL) {
					suhosin_log(S_FILES, "unable to execute fileupload verification script %s - file dropped", sname);
					if (!SUHOSIN_G(simulation)) {
						goto continue_with_failure;
					} else {
						goto continue_with_next;
					}
				}

				retval = FAILURE;

				/* read and forget the result */
				while (1) {
					int readbytes = fread(cmd, 1, sizeof(cmd), in);
					if (readbytes<=0) {
						break;
					}
					if (first) {
						if (strncmp(cmd, "sh: ", 4) == 0) {
							/* assume this is an error */
							suhosin_log(S_FILES, "error while executing fileupload verification script %s - file dropped", sname);
							if (!SUHOSIN_G(simulation)) {
								goto continue_with_failure;
							} else {
								goto continue_with_next;
							}
						} else {
							retval = atoi(cmd) == 1 ? SUCCESS : FAILURE;
							first = 0;
						}
					}
				}
				pclose(in);
			}

			if (retval != SUCCESS) {
				suhosin_log(S_FILES, "fileupload verification script disallows file - file dropped");
				if (!SUHOSIN_G(simulation)) {
					goto continue_with_failure;
				}
			}

			SUHOSIN_G(num_uploads)++;
			break;

		case MULTIPART_EVENT_END:
			/* nothing todo */
			break;

		default:
			/* unknown: return failure */
			goto continue_with_failure;
	}
continue_with_next:
#if HAVE_RFC1867_CALLBACK
	if (php_rfc1867_callback != NULL) {
		return php_rfc1867_callback(event, event_data, extra TSRMLS_CC);
	}
#endif
	return SUCCESS;
continue_with_failure:
	SUHOSIN_G(abort_request) = 1;
	return FAILURE;
}



/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
