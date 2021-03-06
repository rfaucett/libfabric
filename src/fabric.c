/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006-2015 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 Intel Corp., Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include <rdma/fi_errno.h>
#include "fi.h"
#include "prov.h"
#include <rdma/fi_log.h>

#ifdef HAVE_LIBDL
#include <dlfcn.h>
#endif

struct fi_prov {
	struct fi_prov		*next;
	struct fi_provider	*provider;
	void			*dlhandle;
};

static struct fi_prov *fi_getprov(const char *prov_name);

static struct fi_prov *prov_head, *prov_tail;
int init = 0;
static pthread_mutex_t ini_lock = PTHREAD_MUTEX_INITIALIZER;

static struct fi_filter prov_filter;

struct fi_provider core_prov = {
	.name = "core",
	.version = 1,
	.fi_version = FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION)
};


static int fi_find_name(char **names, const char *name)
{
	int i;

	for (i = 0; names[i]; i++) {
		if (!strcmp(name, names[i]))
			return i;
	}
	return -1;
}

int fi_apply_filter(struct fi_filter *filter, const char *name)
{
	if (filter->names) {
		if (fi_find_name(filter->names, name) >= 0)
			return filter->negated ? 1 : 0;

		return filter->negated ? 0 : 1;
	}
	return 0;
}

static void cleanup_provider(struct fi_provider *provider, void *dlhandle)
{
	if (provider) {
		fi_param_undefine(provider);

		if (provider->cleanup)
			provider->cleanup();
	}

#ifdef HAVE_LIBDL
	if (dlhandle)
		dlclose(dlhandle);
#endif
}

static int fi_register_provider(struct fi_provider *provider, void *dlhandle)
{
	struct fi_prov_context *ctx;
	struct fi_prov *prov;
	int ret;

	if (!provider) {
		ret = -FI_EINVAL;
		goto cleanup;
	}

	FI_INFO(&core_prov, FI_LOG_CORE,
	       "registering provider: %s (%d.%d)\n", provider->name,
	       FI_MAJOR(provider->version), FI_MINOR(provider->version));

	if (FI_MAJOR(provider->fi_version) != FI_MAJOR_VERSION ||
	    FI_MINOR(provider->fi_version) > FI_MINOR_VERSION) {
		FI_INFO(&core_prov, FI_LOG_CORE,
		       "provider has unsupported FI version (provider %d.%d != libfabric %d.%d); ignoring\n",
		       FI_MAJOR(provider->fi_version),
		       FI_MINOR(provider->fi_version), FI_MAJOR_VERSION,
		       FI_MINOR_VERSION);

		ret = -FI_ENOSYS;
		goto cleanup;
	}

	if (fi_apply_filter(&prov_filter, provider->name)) {
		FI_INFO(&core_prov, FI_LOG_CORE,
			"\"%s\" filtered by provider include/exclude list, skipping\n",
			provider->name);
		ret = -FI_ENODEV;
		goto cleanup;
	}

	if (fi_apply_filter(&prov_log_filter, provider->name)) {
		ctx = (struct fi_prov_context *) &provider->context;
		ctx->disable_logging = 1;
	}

	prov = fi_getprov(provider->name);
	if (prov) {
		/* If this provider is older than an already-loaded
		 * provider of the same name, then discard this one.
		 */
		if (FI_VERSION_GE(prov->provider->version, provider->version)) {
			FI_INFO(&core_prov, FI_LOG_CORE,
			       "a newer %s provider was already loaded; ignoring this one\n",
			       provider->name);
			ret = -FI_EALREADY;
			goto cleanup;
		}

		/* This provider is newer than an already-loaded
		 * provider of the same name, so discard the
		 * already-loaded one.
		 */
		FI_INFO(&core_prov, FI_LOG_CORE,
		       "an older %s provider was already loaded; keeping this one and ignoring the older one\n",
		       provider->name);
		cleanup_provider(prov->provider, prov->dlhandle);

		prov->dlhandle = dlhandle;
		prov->provider = provider;
		return 0;
	}

	prov = calloc(sizeof *prov, 1);
	if (!prov) {
		ret = -FI_ENOMEM;
		goto cleanup;
	}

	prov->dlhandle = dlhandle;
	prov->provider = provider;
	if (prov_tail)
		prov_tail->next = prov;
	else
		prov_head = prov;
	prov_tail = prov;
	return 0;

cleanup:
	cleanup_provider(provider, dlhandle);
	return ret;
}

#ifdef HAVE_LIBDL
static int lib_filter(const struct dirent *entry)
{
	size_t l = strlen(entry->d_name);
	size_t sfx = sizeof (FI_LIB_SUFFIX) - 1;

	if (l > sfx)
		return !strcmp(&(entry->d_name[l-sfx]), FI_LIB_SUFFIX);
	else
		return 0;
}
#endif

/* split the given string "s" using the specified delimiter(s) in the string
 * "delim" and return an array of strings.  The array is terminated with a NULL
 * pointer.  You can clean this array up with a call to free_string_array().
 *
 * Returns NULL on failure.
 */
static char **split_and_alloc(const char *s, const char *delim)
{
	int i, n;
	char *tmp;
	char *dup = NULL;
	char **arr = NULL;

	if (!s || !delim)
		return NULL;

	dup = strdup(s);
	if (!dup) {
		FI_WARN(&core_prov, FI_LOG_CORE, "failed to allocate memory\n");
		return NULL;
	}

	/* compute the array size */
	n = 1;
	for (tmp = dup; *tmp != '\0'; ++tmp) {
		for (i = 0; delim[i] != '\0'; ++i) {
			if (*tmp == delim[i]) {
				++n;
				break;
			}
		}
	}

	/* +1 to leave space for NULL terminating pointer */
	arr = calloc(n + 1, sizeof(*arr));
	if (!arr) {
		FI_WARN(&core_prov, FI_LOG_CORE, "failed to allocate memory\n");
		goto cleanup;
	}

	/* set array elts to point inside the dup'ed string */
	for (tmp = dup, i = 0; tmp != NULL; ++i) {
		arr[i] = strsep(&tmp, delim);
	}
	assert(i == n);

	return arr;

cleanup:
	free(dup);
	free(arr);
	return NULL;
}

/* see split_and_alloc() */
static void free_string_array(char **s)
{
	/* all strings are allocated from the same strdup'ed slab, so just free
	 * the first element */
	if (s != NULL)
		free(s[0]);

	/* and then the actual array of pointers */
	free(s);
}

void fi_free_filter(struct fi_filter *filter)
{
	free_string_array(filter->names);
}

void fi_create_filter(struct fi_filter *filter, const char *raw_filter)
{
	memset(filter, 0, sizeof *filter);
	if (raw_filter == NULL)
		return;

	if (*raw_filter == '^') {
		filter->negated = 1;
		++raw_filter;
	}

	filter->names = split_and_alloc(raw_filter, ",");
	if (!filter->names)
		FI_WARN(&core_prov, FI_LOG_CORE,
			"unable to parse filter from: %s\n", raw_filter);
}

#ifdef HAVE_LIBDL
static void fi_ini_dir(const char *dir)
{
	int n = 0;
	char *lib;
	void *dlhandle;
	struct dirent **liblist = NULL;
	struct fi_provider* (*inif)(void);

	n = scandir(dir, &liblist, lib_filter, NULL);
	if (n < 0)
		goto libdl_done;

	while (n--) {
		if (asprintf(&lib, "%s/%s", dir, liblist[n]->d_name) < 0) {
			FI_WARN(&core_prov, FI_LOG_CORE,
			       "asprintf failed to allocate memory\n");
			goto libdl_done;
		}
		FI_DBG(&core_prov, FI_LOG_CORE, "opening provider lib %s\n", lib);

		dlhandle = dlopen(lib, RTLD_NOW);
		free(liblist[n]);
		if (dlhandle == NULL) {
			FI_WARN(&core_prov, FI_LOG_CORE,
			       "dlopen(%s): %s\n", lib, dlerror());
			free(lib);
			continue;
		}
		free(lib);

		inif = dlsym(dlhandle, "fi_prov_ini");
		if (inif == NULL) {
			FI_WARN(&core_prov, FI_LOG_CORE, "dlsym: %s\n", dlerror());
			dlclose(dlhandle);
		} else
			fi_register_provider((inif)(), dlhandle);
	}

libdl_done:
	while (n-- > 0)
		free(liblist[n]);
	free(liblist);
}
#endif

void fi_ini(void)
{
	char *param_val = NULL;

	pthread_mutex_lock(&ini_lock);

	if (init)
		goto unlock;

	fi_param_init();
	fi_log_init();

	fi_param_define(NULL, "provider", FI_PARAM_STRING,
			"Only use specified provider (default: all available)");
	fi_param_get_str(NULL, "provider", &param_val);
	fi_create_filter(&prov_filter, param_val);

#ifdef HAVE_LIBDL
	int n = 0;
	char **dirs;
	char *provdir = NULL;
	void *dlhandle;

	/* If dlopen fails, assume static linking and just return
	   without error */
	dlhandle = dlopen(NULL, RTLD_NOW);
	if (dlhandle == NULL) {
		goto libdl_done;
	}
	dlclose(dlhandle);

	fi_param_define(NULL, "provider_path", FI_PARAM_STRING,
			"Search for providers in specific path (default: " PROVDLDIR ")");
	fi_param_get_str(NULL, "provider_path", &provdir);
	if (!provdir)
		provdir = PROVDLDIR;

	dirs = split_and_alloc(provdir, ":");
	for (n = 0; dirs[n]; ++n) {
		fi_ini_dir(dirs[n]);
	}
	free_string_array(dirs);
libdl_done:
#endif

	fi_register_provider(PSM_INIT, NULL);
	fi_register_provider(USNIC_INIT, NULL);
	fi_register_provider(VERBS_INIT, NULL);
        /* Initialize the sockets provider last.  This will result in
           it being the least preferred provider. */
	fi_register_provider(SOCKETS_INIT, NULL);
	init = 1;

unlock:
	pthread_mutex_unlock(&ini_lock);
}

static void __attribute__((destructor)) fi_fini(void)
{
	struct fi_prov *prov;

	if (!init)
		return;

	while (prov_head) {
		prov = prov_head;
		prov_head = prov->next;
		cleanup_provider(prov->provider, prov->dlhandle);
		free(prov);
	}

	fi_free_filter(&prov_filter);
	fi_log_fini();
	fi_param_fini();
}

static struct fi_prov *fi_getprov(const char *prov_name)
{
	struct fi_prov *prov;

	for (prov = prov_head; prov; prov = prov->next) {
		if (!strcmp(prov_name, prov->provider->name))
			return prov;
	}

	return NULL;
}

__attribute__((visibility ("default")))
void DEFAULT_SYMVER_PRE(fi_freeinfo)(struct fi_info *info)
{
	struct fi_info *next;

	for (; info; info = next) {
		next = info->next;

		free(info->src_addr);
		free(info->dest_addr);
		free(info->tx_attr);
		free(info->rx_attr);
		free(info->ep_attr);
		if (info->domain_attr) {
			free(info->domain_attr->name);
			free(info->domain_attr);
		}
		if (info->fabric_attr) {
			free(info->fabric_attr->name);
			free(info->fabric_attr->prov_name);
			free(info->fabric_attr);
		}
		free(info);
	}
}
DEFAULT_SYMVER(fi_freeinfo_, fi_freeinfo);

__attribute__((visibility ("default")))
int DEFAULT_SYMVER_PRE(fi_getinfo)(uint32_t version, const char *node, const char *service,
	       uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	struct fi_prov *prov;
	struct fi_info *tail, *cur;
	int ret = -FI_ENODATA;

	if (!init)
		fi_ini();

	if (FI_VERSION_LT(fi_version(), version)) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Requested version is newer than library\n");
		return -FI_ENOSYS;
	}

	*info = tail = NULL;
	for (prov = prov_head; prov; prov = prov->next) {
		if (!prov->provider->getinfo)
			continue;

		if (hints && hints->fabric_attr && hints->fabric_attr->prov_name &&
		    strcmp(prov->provider->name, hints->fabric_attr->prov_name))
			continue;

		ret = prov->provider->getinfo(version, node, service, flags,
					      hints, &cur);
		if (ret) {
			FI_WARN(&core_prov, FI_LOG_CORE,
			       "fi_getinfo: provider %s returned -%d (%s)\n",
			       prov->provider->name, -ret, fi_strerror(-ret));
			if (ret == -FI_ENODATA) {
				continue;
			} else {
				/* a provider has an error, clean up and bail */
				fi_freeinfo(*info);
				*info = NULL;
				return ret;
			}
		}

		if (!*info)
			*info = cur;
		else
			tail->next = cur;
		for (tail = cur; tail->next; tail = tail->next) {
			tail->fabric_attr->prov_name = strdup(prov->provider->name);
			tail->fabric_attr->prov_version = prov->provider->version;
		}
		tail->fabric_attr->prov_name = strdup(prov->provider->name);
		tail->fabric_attr->prov_version = prov->provider->version;
	}

	return *info ? 0 : ret;
}
DEFAULT_SYMVER(fi_getinfo_, fi_getinfo);

static struct fi_info *fi_allocinfo_internal(void)
{
	struct fi_info *info;

	info = calloc(1, sizeof(*info));
	if (!info)
		return NULL;

	info->tx_attr = calloc(1, sizeof(*info->tx_attr));
	info->rx_attr = calloc(1, sizeof(*info->rx_attr));
	info->ep_attr = calloc(1, sizeof(*info->ep_attr));
	info->domain_attr = calloc(1, sizeof(*info->domain_attr));
	info->fabric_attr = calloc(1, sizeof(*info->fabric_attr));
	if (!info->tx_attr|| !info->rx_attr || !info->ep_attr ||
	    !info->domain_attr || !info->fabric_attr)
		goto err;

	return info;
err:
	fi_freeinfo(info);
	return NULL;
}


__attribute__((visibility ("default")))
struct fi_info *DEFAULT_SYMVER_PRE(fi_dupinfo)(const struct fi_info *info)
{
	struct fi_info *dup;

	if (!info)
		return fi_allocinfo_internal();

	dup = calloc(1, sizeof(*dup));
	if (dup == NULL) {
		return NULL;
	}
	*dup = *info;
	dup->src_addr = NULL;
	dup->dest_addr = NULL;
	dup->tx_attr = NULL;
	dup->rx_attr = NULL;
	dup->ep_attr = NULL;
	dup->domain_attr = NULL;
	dup->fabric_attr = NULL;
	dup->next = NULL;

	if (info->src_addr != NULL) {
		dup->src_addr = calloc(1, dup->src_addrlen);
		if (dup->src_addr == NULL) {
			goto fail;
		}
		memcpy(dup->src_addr, info->src_addr, info->src_addrlen);
	}
	if (info->dest_addr != NULL) {
		dup->dest_addr = calloc(1, dup->dest_addrlen);
		if (dup->dest_addr == NULL) {
			goto fail;
		}
		memcpy(dup->dest_addr, info->dest_addr, info->dest_addrlen);
	}
	if (info->tx_attr != NULL) {
		dup->tx_attr = calloc(1, sizeof(*dup->tx_attr));
		if (dup->tx_attr == NULL) {
			goto fail;
		}
		*dup->tx_attr = *info->tx_attr;
	}
	if (info->rx_attr != NULL) {
		dup->rx_attr = calloc(1, sizeof(*dup->rx_attr));
		if (dup->rx_attr == NULL) {
			goto fail;
		}
		*dup->rx_attr = *info->rx_attr;
	}
	if (info->ep_attr != NULL) {
		dup->ep_attr = calloc(1, sizeof(*dup->ep_attr));
		if (dup->ep_attr == NULL) {
			goto fail;
		}
		*dup->ep_attr = *info->ep_attr;
	}
	if (info->domain_attr) {
		dup->domain_attr = calloc(1, sizeof(*dup->domain_attr));
		if (dup->domain_attr == NULL) {
			goto fail;
		}
		*dup->domain_attr = *info->domain_attr;
		if (info->domain_attr->name != NULL) {
			dup->domain_attr->name =
				strdup(info->domain_attr->name);
			if (dup->domain_attr->name == NULL) {
				goto fail;
			}
		}
	}
	if (info->fabric_attr) {
		dup->fabric_attr = calloc(1, sizeof(*dup->fabric_attr));
		if (dup->fabric_attr == NULL) {
			goto fail;
		}
		*dup->fabric_attr = *info->fabric_attr;
		if (info->fabric_attr->name != NULL) {
			dup->fabric_attr->name =
				strdup(info->fabric_attr->name);
			if (dup->fabric_attr->name == NULL) {
				goto fail;
			}
		}
		if (info->fabric_attr->prov_name != NULL) {
			dup->fabric_attr->prov_name =
				strdup(info->fabric_attr->prov_name);
			if (dup->fabric_attr->prov_name == NULL) {
				goto fail;
			}
		}
	}
	return dup;

fail:
	fi_freeinfo(dup);
	return NULL;
}
DEFAULT_SYMVER(fi_dupinfo_, fi_dupinfo);

__attribute__((visibility ("default")))
int DEFAULT_SYMVER_PRE(fi_fabric)(struct fi_fabric_attr *attr, struct fid_fabric **fabric, void *context)
{
	struct fi_prov *prov;

	if (!attr || !attr->prov_name || !attr->name)
		return -FI_EINVAL;

	if (!init)
		fi_ini();

	prov = fi_getprov(attr->prov_name);
	if (!prov || !prov->provider->fabric)
		return -FI_ENODEV;

	return prov->provider->fabric(attr, fabric, context);
}
DEFAULT_SYMVER(fi_fabric_, fi_fabric);

__attribute__((visibility ("default")))
uint32_t DEFAULT_SYMVER_PRE(fi_version)(void)
{
	return FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION);
}
DEFAULT_SYMVER(fi_version_, fi_version);

static const char *const errstr[] = {
	[FI_EOTHER - FI_ERRNO_OFFSET] = "Unspecified error",
	[FI_ETOOSMALL - FI_ERRNO_OFFSET] = "Provided buffer is too small",
	[FI_EOPBADSTATE - FI_ERRNO_OFFSET] = "Operation not permitted in current state",
	[FI_EAVAIL - FI_ERRNO_OFFSET]  = "Error available",
	[FI_EBADFLAGS - FI_ERRNO_OFFSET] = "Flags not supported",
	[FI_ENOEQ - FI_ERRNO_OFFSET] = "Missing or unavailable event queue",
	[FI_EDOMAIN - FI_ERRNO_OFFSET] = "Invalid resource domain",
	[FI_ENOCQ - FI_ERRNO_OFFSET] = "Missing or unavailable completion queue",
	[FI_ECRC - FI_ERRNO_OFFSET] = "CRC error",
	[FI_ETRUNC - FI_ERRNO_OFFSET] = "Truncation error",
	[FI_ENOKEY - FI_ERRNO_OFFSET] = "Required key not available",
};

__attribute__((visibility ("default")))
const char *DEFAULT_SYMVER_PRE(fi_strerror)(int errnum)
{
	if (errnum < FI_ERRNO_OFFSET)
		return strerror(errnum);
	else if (errnum < FI_ERRNO_MAX)
		return errstr[errnum - FI_ERRNO_OFFSET];
	else
		return errstr[FI_EOTHER - FI_ERRNO_OFFSET];
}
DEFAULT_SYMVER(fi_strerror_, fi_strerror);
