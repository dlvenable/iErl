/*
 * %CopyrightBegin%
 * 
 * Copyright Ericsson AB 2006-2009. All Rights Reserved.
 * 
 * The contents of this file are subject to the Erlang Public License,
 * Version 1.1, (the "License"); you may not use this file except in
 * compliance with the License. You should have received a copy of the
 * Erlang Public License along with this software. If not, it can be
 * retrieved online at http://www.erlang.org/.
 * 
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 * 
 * %CopyrightEnd%
 */

/* 
 * Interface functions to the dynamic linker using dl* functions.
 * (As far as I know it works on SunOS 4, 5, Linux and FreeBSD. /Seb) 
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "sys.h"
#include "erl_vm.h"
#include "global.h"
#include "erl_nif.h"
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif


/* some systems do not have RTLD_NOW defined, and require the "mode"
 * argument to dload() always be 1.
 */
#ifndef RTLD_NOW
#  define RTLD_NOW 1
#endif

#define MAX_NAME_LEN 255      /* XXX should we get the system path size? */
#define EXT_LEN      3
#define FILE_EXT     ".so"    /* extension appended to the filename */

static char **errcodes = NULL;
static int num_errcodes = 0;
static int num_errcodes_allocated = 0;

#define my_strdup(WHAT) my_strdup_in(ERTS_ALC_T_DDLL_ERRCODES, WHAT);

static char *my_strdup_in(ErtsAlcType_t type, char *what)
{
    char *res = erts_alloc(type, strlen(what) + 1);
    strcpy(res, what);
    return res;
}


static int find_errcode(char *string, ErtsSysDdllError* err) 
{
    int i;

    if (err != NULL) {
	erts_sys_ddll_free_error(err); /* in case we ignored an earlier error */
	err->str = my_strdup_in(ERTS_ALC_T_DDLL_TMP_BUF, string);
	return 0;
    }
    for(i=0;i<num_errcodes;++i) {
	if (!strcmp(string, errcodes[i])) {
	    return i;
	}
    }
    if (num_errcodes_allocated == num_errcodes) {
	errcodes = (num_errcodes_allocated == 0) 
	    ? erts_alloc(ERTS_ALC_T_DDLL_ERRCODES, 
			 (num_errcodes_allocated = 10) * sizeof(char *)) 
	    : erts_realloc(ERTS_ALC_T_DDLL_ERRCODES, errcodes,
			   (num_errcodes_allocated += 10) * sizeof(char *));
    }
    errcodes[num_errcodes++] = my_strdup(string);
    return (num_errcodes - 1);
}

void erl_sys_ddll_init(void) {
#if defined(HAVE_DLOPEN) && defined(ERTS_NEED_DLOPEN_BEFORE_DLERROR)
    /*
     * dlopen() needs to be called before we make the first call to
     * dlerror(); otherwise, dlerror() might dump core. At least
     * some versions of linuxthread suffer from this bug.
     */
    void *handle = dlopen("/nonexistinglib", RTLD_NOW);
    if (handle)
	dlclose(handle);
#endif    
    return;
}

/* 
 * Open a shared object
 */
int erts_sys_ddll_open2(char *full_name, void **handle, ErtsSysDdllError* err)
{
    //fprintf(stderr, "Dynamic load attempt: %s\n", full_name);
#ifndef EMONK_DISABLED
    if(strcmp("emonk", full_name) == 0) {
        *handle = (void*) 1;
        return ERL_DE_NO_ERROR;
    }
#endif
    if(strcmp("ejson", full_name) == 0) {
        *handle = (void*) 2;
        return ERL_DE_NO_ERROR;
    }
    if(strcmp("snappy", full_name) == 0) {
        *handle = (void*) 3;
        return ERL_DE_NO_ERROR;
    }
    if(strcmp("ios", full_name) == 0) {
        *handle = (void*) 4;
        return ERL_DE_NO_ERROR;
    }
    if(strcmp("objc_dispatch", full_name) == 0) {
        *handle = (void*) 5;
        return ERL_DE_NO_ERROR;
    }
    err->str = my_strdup_in(ERTS_ALC_T_DDLL_TMP_BUF,"Cannot load DLLs on iOS");
    return ERL_DE_ERROR_NO_DDLL_FUNCTIONALITY;
}

int erts_sys_ddll_open_noext(char *dlname, void **handle, ErtsSysDdllError* err)
{
	return erts_sys_ddll_open2(dlname, handle, err);
}

/* 
 * Find a symbol in the shared object
 */

int erts_sys_ddll_sym2(void *handle, char *func_name, void **function,
		       ErtsSysDdllError* err)
{
    return ERL_DE_ERROR_NO_DDLL_FUNCTIONALITY;
}

/* XXX:PaN These two will be changed with new driver interface! */

/* 
 * Load the driver init function, might appear under different names depending on object arch... 
 */

int erts_sys_ddll_load_driver_init(void *handle, void **function)
{
    void *fn;
    int res;
    if ((res = erts_sys_ddll_sym2(handle, "driver_init", &fn, NULL)) != ERL_DE_NO_ERROR) {
	res = erts_sys_ddll_sym2(handle, "_driver_init", &fn, NULL);
    }
    if (res == ERL_DE_NO_ERROR) {
	*function = fn;
    }
    return res;
}
//NIF SUPPORT
ErlNifEntry* emonk_init(void);
ErlNifEntry* ejson_init(void);
ErlNifEntry* snappy_init(void);
ErlNifEntry* couch_ios_init(void);
ErlNifEntry* objc_dispatch_init(void);
int erts_sys_ddll_load_nif_init(void *handle, void **function, ErtsSysDdllError* err)
{
    int res = ERL_DE_ERROR_NO_DDLL_FUNCTIONALITY;
#ifndef EMONK_DISABLED
    if((size_t)handle == 1) {
        //fprintf(stderr, "Loaded NIF: emonk.\n");
        *function = emonk_init;
        res = ERL_DE_NO_ERROR;
    }
#endif
    if((size_t)handle == 2) {
        //fprintf(stderr, "Loaded NIF: ejson.\n");
        *function = ejson_init;
        res = ERL_DE_NO_ERROR;
    }
    if((size_t)handle == 3) {
        //fprintf(stderr, "Loaded NIF: snappy.\n");
        *function = snappy_init;
        res = ERL_DE_NO_ERROR;
    }
    if((size_t)handle == 4) {
        //fprintf(stderr, "Loaded NIF: ios.\n");
        *function = couch_ios_init;
        res = ERL_DE_NO_ERROR;
    }
    if((size_t)handle == 5) {
        //fprintf(stderr, "Loaded NIF: objc_dispatch.\n");
        *function = objc_dispatch_init;
        res = ERL_DE_NO_ERROR;
    }
    return res;
}

/* 
 * Call the driver_init function, whatever it's really called, simple on unix... 
*/
void *erts_sys_ddll_call_init(void *function) {
    void *(*initfn)(void) = function;
    return (*initfn)();
}
void *erts_sys_ddll_call_nif_init(void *function) {
    return erts_sys_ddll_call_init(function);
}



/* 
 * Close a chared object
 */
int erts_sys_ddll_close2(void *handle, ErtsSysDdllError* err)
{
#if defined(HAVE_DLOPEN)
    int ret;
    char *s;
    dlerror();
    if (dlclose(handle) == 0) {
	ret = ERL_DE_NO_ERROR;
    } else {
	if ((s = dlerror()) == NULL) {
	    find_errcode("unspecified error", err);
	    ret = ERL_DE_ERROR_UNSPECIFIED;
	} else {
	    ret = ERL_DE_DYNAMIC_ERROR_OFFSET - find_errcode(s, err);
	}
    }
    return ret;
#else
    return ERL_DE_ERROR_NO_DDLL_FUNCTIONALITY;
#endif
}


/*
 * Return string that describes the (current) error
 */
char *erts_sys_ddll_error(int code)
{
    int actual_code;

    if (code > ERL_DE_DYNAMIC_ERROR_OFFSET) {
	return "Unspecified error";
    }
    actual_code = -1*(code - ERL_DE_DYNAMIC_ERROR_OFFSET);
#if defined(HAVE_DLOPEN)
    {
	char *msg;

	if (actual_code >= num_errcodes) {
	    msg = "Unknown dlload error";
	} else {
	    msg = errcodes[actual_code];
	}
	return msg;
    }
#endif
    return "no error";
}

void erts_sys_ddll_free_error(ErtsSysDdllError* err)
{   
    if (err->str != NULL) {
	erts_free(ERTS_ALC_T_DDLL_TMP_BUF, err->str);
    }
}

