/*
 * Copyright (c) 2014, Cisco Systems, Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <asm/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_prov.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>
#include "fi.h"
#include "fi_enosys.h"

#include "usnic_direct.h"
#include "usd.h"
#include "usdf.h"
#include "usdf_endpoint.h"
#include "usdf_progress.h"

static int
usdf_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct usdf_ep *ep;

	ep = ep_fidtou(fid);

	switch (bfid->fclass) {

	case FI_CLASS_AV:
		if (ep->ep_av != NULL) {
			return -FI_EINVAL;
		}
		ep->ep_av = av_fidtou(bfid);
		break;

	case FI_CLASS_CQ:
		if (flags & FI_SEND) {
			if (ep->ep_wcq != NULL) {
				return -FI_EINVAL;
			}
			ep->ep_wcq = cq_fidtou(bfid);
		}

		if (flags & FI_RECV) {
			if (ep->ep_rcq != NULL) {
				return -FI_EINVAL;
			}
			ep->ep_rcq = cq_fidtou(bfid);
		}
		break;

	case FI_CLASS_EQ:
printf("bind EQ to ep!\n");
		if (ep->ep_eq != NULL) {
			return -FI_EINVAL;
		}
		ep->ep_eq = eq_fidtou(bfid);
		atomic_inc(&ep->ep_eq->eq_refcnt);
		break;
	default:
		return -FI_EINVAL;
	}

	return 0;
}

static int
usdf_ep_close(fid_t fid)
{
	struct usdf_ep *ep;

	ep = ep_fidtou(fid);

	if (atomic_get(&ep->ep_refcnt) > 0) {
		return -FI_EBUSY;
	}

	if (ep->ep_qp != NULL) {
		usd_destroy_qp(ep->ep_qp);
	}
	atomic_dec(&ep->ep_domain->dom_refcnt);
	if (ep->ep_eq != NULL) {
		atomic_dec(&ep->ep_eq->eq_refcnt);
	}
	
	free(ep);
	return 0;
}

struct fi_ops usdf_ep_ops = {
	.size = sizeof(struct fi_ops),
	.close = usdf_ep_close,
	.bind = usdf_ep_bind,
	.sync = fi_no_sync,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};

int
usdf_ep_port_bind(struct usdf_ep *ep, struct fi_info *info)
{
	struct sockaddr_in *sin;
	socklen_t addrlen;
	int ret;

	sin = (struct sockaddr_in *)info->src_addr;
	ret = bind(ep->ep_sock, (struct sockaddr *)sin, sizeof(*sin));
	if (ret == -1) {
		return -errno;
	}

	addrlen = sizeof(*sin);
	ret = getsockname(ep->ep_sock, (struct sockaddr *)sin, &addrlen);
	if (ret == -1) {
		return -errno;
	}

	return 0;
}

int
usdf_endpoint_open(struct fid_domain *domain, struct fi_info *info,
	    struct fid_ep **ep_o, void *context)
{
	switch (info->ep_type) {
	case FI_EP_DGRAM:
		return usdf_ep_dgram_open(domain, info, ep_o, context);
	case FI_EP_MSG:
		return usdf_ep_msg_open(domain, info, ep_o, context);
	default:
		return -FI_ENODEV;
	}
}

/*
 * Passive endpoint
 */

int
usdf_passive_ep_close(fid_t fid)
{
	struct usdf_pep *pep;

	pep = pep_fidtou(fid);
	if (atomic_get(&pep->pep_refcnt) > 0) {
		return -FI_EBUSY;
	}

	close(pep->pep_sock);
	if (&pep->pep_eq != NULL) {
		atomic_dec(&pep->pep_eq->eq_refcnt);
	}
	atomic_dec(&pep->pep_fabric->fab_refcnt);
	free(pep);

	return 0;
}

int
usdf_passive_ep_bind(fid_t fid, fid_t bfid, uint64_t flags)
{
	struct usdf_pep *pep;

	pep = pep_fidtou(fid);

	switch (bfid->fclass) {

	case FI_CLASS_EQ:
printf("bind EQ!\n");
		if (pep->pep_eq != NULL) {
			return -FI_EINVAL;
		}
		pep->pep_eq = eq_fidtou(bfid);
		atomic_inc(&pep->pep_eq->eq_refcnt);
		break;
		
	default:
		return -FI_EINVAL;
	}

	return 0;
}

static int
usdf_pep_listen_cb(void *v)
{
	struct usdf_pep *pep;
	struct sockaddr_in sin;
	socklen_t socklen;
	int ret;

	pep = v;

	socklen = sizeof(sin);
	ret = accept(pep->pep_sock, &sin, &socklen);
	printf("connreq on %p, ret = %d (%x)!\n", pep, ret, sin.sin_addr.s_addr);

	return 0;
}

int
usdf_pep_listen(struct fid_pep *fpep)
{
	struct usdf_pep *pep;
	struct epoll_event ev;
	struct usdf_fabric *fp;
	int ret;

	pep = pep_ftou(fpep);
	fp = pep->pep_fabric;

	ret = listen(pep->pep_sock, pep->pep_backlog);
	if (ret != 0) {
		ret = -errno;
	}

	pep->pep_pollitem->pi_rtn = &usdf_pep_listen_cb;
	pep->pep_pollitem->pi_context = pep;
	ev.events = EPOLLIN;
	ev.data.ptr = pep->pep_pollitem;
printf("add ptr = %p\n", ev.data.ptr);
	ret = epoll_ctl(fp->fab_epollfd, EPOLL_CTL_ADD, pep->pep_sock, &ev);
	if (ret == -1) {
		return -errno;
	}
printf("listen ret=%d\n", ret);

	return ret;
}

ssize_t
usdf_pep_cancel(fid_t fid, void *context)
{
	return -FI_EINVAL;
}

int
usdf_pep_accept(struct fid_ep *ep, const void *param, size_t paramlen)
{
	return 0;
}

int
usdf_pep_reject(struct fid_pep *pep, fi_connreq_t connreq,
		const void *param, size_t paramlen)
{
	return 0;
}

struct fi_ops usdf_pep_ops = {
	.size = sizeof(struct fi_ops),
	.close = usdf_passive_ep_close,
	.bind = usdf_passive_ep_bind,
	.sync = fi_no_sync,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};

static struct fi_ops_ep usdf_pep_base_ops = {
	.size = sizeof(struct fi_ops_ep),
	.enable = fi_no_enable,
	.cancel = usdf_pep_cancel,
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
};

static struct fi_ops_cm usdf_pep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.getname = fi_no_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = usdf_pep_listen,
	.accept = usdf_pep_accept,
	.reject = usdf_pep_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
	.leave = fi_no_leave,
};

int
usdf_passive_ep_open(struct fid_fabric *fabric, struct fi_info *info,
	    struct fid_pep **pep_o, void *context)
{
	struct usdf_pep *pep;
	struct usdf_fabric *fp;
	int ret;

	if (info->ep_type != FI_EP_MSG) {
		return -FI_ENODEV;
	}

	if ((info->caps & ~USDF_MSG_CAPS) != 0) {
		return -FI_EBADF;
	}

	fp = fab_ftou(fabric);

	pep = calloc(1, sizeof(*pep));
	if (pep == NULL) {
		return -FI_ENOMEM;
	}
	pep->pep_pollitem = calloc(1, sizeof(*pep->pep_pollitem));
	if (pep->pep_pollitem == NULL) {
		ret = -FI_ENOMEM;
		goto fail;
	}

	pep->pep_fid.fid.fclass = FI_CLASS_PEP;
	pep->pep_fid.fid.context = context;
	pep->pep_fid.fid.ops = &usdf_pep_ops;
	pep->pep_fid.ops = &usdf_pep_base_ops;
	pep->pep_fid.cm = &usdf_pep_cm_ops;
	pep->pep_fabric = fp;

	pep->pep_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (pep->pep_sock == -1) {
		ret = -errno;
		goto fail;
	}
        ret = fcntl(pep->pep_sock, F_GETFL, 0);
        if (ret == -1) {
                ret = -errno;
                goto fail;
        }
        ret = fcntl(pep->pep_sock, F_SETFL, ret | O_NONBLOCK);
        if (ret == -1) {
                ret = -errno;
                goto fail;
        }

	ret = bind(pep->pep_sock, (struct sockaddr *)info->src_addr,
			info->src_addrlen);
	if (ret == -1) {
		ret = -errno;
		goto fail;
	}
	pep->pep_backlog = 10;

	atomic_init(&pep->pep_refcnt, 0);
	atomic_inc(&fp->fab_refcnt);

	*pep_o = pep_utof(pep);
	return 0;

fail:
	if (pep != NULL) {
		if (pep->pep_sock != -1) {
			close(pep->pep_sock);
		}
		if (pep->pep_pollitem != NULL) {
			free(pep->pep_pollitem);
		}
		free(pep);
	}
	return ret;
}
