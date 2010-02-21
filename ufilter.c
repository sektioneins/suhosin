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

#if !HAVE_RFC1867_CALLBACK
PHP_SUHOSIN_API int (*php_rfc1867_callback)(unsigned int event, void *event_data, void **extra TSRMLS_DC) = NULL;
#endif

static int is_protected_varname(char *var, int var_len)
{
	switch (var_len) {
	    case 18:
		if (memcmp(var, "HTTP_RAW_POST_DATA", 18)==0) goto protected_varname2;
		break;
	    case 17:
		if (memcmp(var, "HTTP_SESSION_VARS", 17)==0) goto protected_varname2;
		break;
	    case 16:
		if (memcmp(var, "HTTP_SERVER_VARS", 16)==0) goto protected_varname2;
		if (memcmp(var, "HTTP_COOKIE_VARS", 16)==0) goto protected_varname2;
		break;
	    case 15:
		if (memcmp(var, "HTTP_POST_FILES", 15)==0) goto protected_varname2;
		break;
	    case 14:
		if (memcmp(var, "HTTP_POST_VARS", 14)==0) goto protected_varname2;
		break;
	    case 13:
		if (memcmp(var, "HTTP_GET_VARS", 13)==0) goto protected_varname2;
		if (memcmp(var, "HTTP_ENV_VARS", 13)==0) goto protected_varname2;
		break;
	    case 8:
		if (memcmp(var, "_SESSION", 8)==0) goto protected_varname2;
		if (memcmp(var, "_REQUEST", 8)==0) goto protected_varname2;
		break;
	    case 7:
		if (memcmp(var, "GLOBALS", 7)==0) goto protected_varname2;
		if (memcmp(var, "_COOKIE", 7)==0) goto protected_varname2;
		if (memcmp(var, "_SERVER", 7)==0) goto protected_varname2;
		break;
	    case 6:
		if (memcmp(var, "_FILES", 6)==0) goto protected_varname2;
		break;
	    case 5:
		if (memcmp(var, "_POST", 5)==0) goto protected_varname2;
		break;
	    case 4:
		if (memcmp(var, "_ENV", 4)==0) goto protected_varname2;
		if (memcmp(var, "_GET", 4)==0) goto protected_varname2;
		break;
	}

	return 0;
protected_varname2:	
	return 1;
}

/* {{{ SAPI_UPLOAD_VARNAME_FILTER_FUNC
 */
static int check_fileupload_varname(char *varname)
{
	char *index, *prev_index = NULL, *var;
	unsigned int var_len, total_len, depth = 0;
	TSRMLS_FETCH();

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
		unsigned int index_length;
		
		depth++;
		index = strchr(index+1, '[');
		
		if (prev_index) {
			index_length = index ? index - 1 - prev_index - 1: strlen(prev_index);
			
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
			prev_index = index;
		}
		
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
	
	if (is_protected_varname(var, var_len)) {
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
		    
			    
			    if (check_fileupload_varname(mefs->name) == FAILURE) {
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
			    size_t i;
			    
			    for (i=0; i<mefd->length; i++) {
				    if (mefd->data[i] < 32 && !isspace(mefd->data[i])) {
					    suhosin_log(S_FILES, "uploaded file contains binary data - file dropped");
					    if (!SUHOSIN_G(simulation)) {
						    goto continue_with_failure;
					    }
				    }
			    }
		    }

		    if (SUHOSIN_G(upload_remove_binary)) {
		    
			    multipart_event_file_data *mefd = (multipart_event_file_data *) event_data;
			    size_t i, j;
			    
			    for (i=0, j=0; i<mefd->length; i++) {
				    if (mefd->data[i] >= 32 || isspace(mefd->data[i])) {
					    mefd->data[j++] = mefd->data[i];
				    }
			    }
			    SDEBUG("removing binary %u %u",i,j);
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
		
			    ap_php_snprintf(cmd, sizeof(cmd), "%s %s", sname, mefe->temp_filename);

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
					    retval = atoi(cmd) == 1 ? SUCCESS : FAILURE;
					    first = 0;
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
