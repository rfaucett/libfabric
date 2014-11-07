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
#include <poll.h>
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
#include "usdf_dgram.h"
#include "usdf_msg.h"

static int
usdf_dgram_ep_enable(struct fid_ep *fep)
{
	struct usdf_ep *ep;
	struct usd_filter filt;
	struct usd_qp_impl *uqp;
	int ret;

	ep = ep_ftou(fep);

	filt.uf_type = USD_FTY_UDP_SOCK;
	filt.uf_filter.uf_udp_sock.u_sock = ep->ep_sock;

	if (ep->ep_caps & USDF_EP_CAP_PIO) {
		ret = usd_create_qp(ep->ep_domain->dom_dev, USD_QTR_UDP, USD_QTY_PIO,
				ep->ep_wcq->cq_cq, 
				ep->ep_rcq->cq_cq, 
				127,	// XXX
				127,	// XXX
				&filt,
				&ep->ep_qp);
	} else {
		ret = -EAGAIN;
	}

	if (ret != 0) {
		ret = usd_create_qp(ep->ep_domain->dom_dev, USD_QTR_UDP, USD_QTY_NORMAL,
				ep->ep_wcq->cq_cq, 
				ep->ep_rcq->cq_cq, 
				ep->ep_wqe,
				ep->ep_rqe,
				&filt,
				&ep->ep_qp);
	}
	if (ret != 0) {
		goto fail;
	}
	ep->ep_qp->uq_context = ep;

	/*
	 * Allocate a memory region big enough to hold a header for each
	 * RQ entry 
	 */
	uqp = to_qpi(ep->ep_qp);
	ep->ep_hdr_ptr = calloc(uqp->uq_rq.urq_num_entries,
			sizeof(ep->ep_hdr_ptr[0]));
	if (ep->ep_hdr_ptr == NULL) {
		ret = -FI_ENOMEM;
		goto fail;
	}

	ret = usd_alloc_mr(ep->ep_domain->dom_dev,
			usd_get_recv_credits(ep->ep_qp) * USDF_HDR_BUF_ENTRY,
			&ep->ep_hdr_buf);
	if (ret != 0) {
		goto fail;
	}

	return 0;

fail:
	if (ep->ep_hdr_ptr != NULL) {
		free(ep->ep_hdr_ptr);
	}
	if (ep->ep_qp != NULL) {
		usd_destroy_qp(ep->ep_qp);
	}
	return ret;
}

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
	if (&ep->ep_eq != NULL) {
		atomic_dec(&ep->ep_eq->eq_refcnt);
	}
	
	free(ep);
	return 0;
}

static struct fi_ops usdf_ep_ops = {
	.size = sizeof(struct fi_ops),
	.close = usdf_ep_close,
	.bind = usdf_ep_bind,
	.sync = fi_no_sync,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};

static struct fi_ops_ep usdf_base_dgram_ops = {
	.size = sizeof(struct fi_ops_ep),
	.enable = usdf_dgram_ep_enable,
	.cancel = fi_no_cancel,
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
};

static struct fi_ops_msg usdf_dgram_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = usdf_dgram_recv,
	.recvv = usdf_dgram_recvv,
	.recvfrom = usdf_dgram_recvfrom,
	.recvmsg = usdf_dgram_recvmsg,
	.send = usdf_dgram_send,
	.sendv = usdf_dgram_sendv,
	.sendto = usdf_dgram_sendto,
	.sendmsg = usdf_dgram_sendmsg,
	.inject = usdf_dgram_inject,
	.injectto = usdf_dgram_injectto,
	.senddata = usdf_dgram_senddata,
	.senddatato = usdf_dgram_senddatato
};

static struct fi_ops_msg usdf_dgram_prefix_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = usdf_dgram_prefix_recv,
	.recvv = usdf_dgram_prefix_recvv,
	.recvfrom = usdf_dgram_recvfrom,
	.recvmsg = usdf_dgram_recvmsg,
	.send = usdf_dgram_send,
	.sendv = usdf_dgram_sendv,
	.sendto = usdf_dgram_sendto,
	.sendmsg = usdf_dgram_sendmsg,
	.inject = usdf_dgram_inject,
	.injectto = usdf_dgram_injectto,
	.senddata = usdf_dgram_senddata,
	.senddatato = usdf_dgram_senddatato
};

static struct fi_ops_cm usdf_cm_dgram_ops = {
	.size = sizeof(struct fi_ops_cm),
	.connect = usdf_cm_dgram_connect,
	.shutdown = usdf_cm_dgram_shutdown,
};

static int
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

static int
usdf_endpoint_open_dgram(struct fid_domain *domain, struct fi_info *info,
	    struct fid_ep **ep_o, void *context)
{
	struct usdf_domain *udp;
	struct usdf_ep *ep;
	int ret;

	if ((info->caps & ~USDF_DGRAM_CAPS) != 0) {
		return -FI_EBADF;
	}

	udp = dom_ftou(domain);

	ep = calloc(1, sizeof(*ep));
	if (ep == NULL) {
		return -FI_ENOMEM;
	}

	ep->ep_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (ep->ep_sock == -1) {
		ret = -errno;
		goto fail;
	}
	if (info->src_addr != NULL) {
		if (info->addr_format == FI_SOCKADDR ||
		    info->addr_format == FI_SOCKADDR_IN) {
			ret = usdf_ep_port_bind(ep, info);
			if (ret != 0) {
				goto fail;
			}
		}
	}

	ep->ep_fid.fid.fclass = FI_CLASS_EP;
	ep->ep_fid.fid.context = context;
	ep->ep_fid.fid.ops = &usdf_ep_ops;
	ep->ep_fid.ops = &usdf_base_dgram_ops;
	ep->ep_fid.cm = &usdf_cm_dgram_ops;
	ep->ep_domain = udp;
	ep->ep_caps = info->caps;
	ep->ep_mode = info->mode;
	if (info->tx_attr != NULL && info->tx_attr->size != 0) {
		ep->ep_wqe = info->tx_attr->size;
	} else {
		ep->ep_wqe = udp->dom_dev_attrs.uda_max_send_credits;
	}
	if (info->rx_attr != NULL && info->rx_attr->size != 0) {
		ep->ep_rqe = info->rx_attr->size;
	} else {
		ep->ep_rqe = udp->dom_dev_attrs.uda_max_recv_credits;
	}

	if (ep->ep_mode & FI_MSG_PREFIX) {
		if (info->ep_attr == NULL) {
			ret = -FI_EBADF;
			goto fail;
		}

		info->ep_attr->msg_prefix_size = USDF_HDR_BUF_ENTRY;
		ep->ep_fid.msg = &usdf_dgram_prefix_ops;
	} else {
		ep->ep_fid.msg = &usdf_dgram_ops;
	}
	atomic_init(&ep->ep_refcnt, 0);
	atomic_inc(&udp->dom_refcnt);

	*ep_o = ep_utof(ep);
	return 0;

fail:
	if (ep != NULL) {
		if (ep->ep_sock != -1) {
			close(ep->ep_sock);
		}
		free(ep);
	}
	return ret;
}

/*
 * Reliable messaging
 */

static int
usdf_msg_ep_getopt(fid_t fid, int level, int optname,
		  void *optval, size_t *optlen)
{
	struct usdf_ep *ep;
	ep = ep_fidtou(fid);
	(void)ep;

	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int
usdf_msg_ep_setopt(fid_t fid, int level, int optname,
		  const void *optval, size_t optlen)
{
	struct usdf_ep *ep;
	ep = ep_fidtou(fid);
	(void)ep;

	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int
usdf_msg_ep_enable(struct fid_ep *fep)
{
	struct usdf_ep *ep;
	struct usd_filter filt;
	struct usd_qp_impl *uqp;
	int ret;

	ep = ep_ftou(fep);

	filt.uf_type = USD_FTY_UDP_SOCK;
	filt.uf_filter.uf_udp_sock.u_sock = ep->ep_sock;

	ret = usd_create_qp(ep->ep_domain->dom_dev,
			USD_QTR_UDP,
			USD_QTY_NORMAL,
			ep->ep_wcq->cq_cq, 
			ep->ep_rcq->cq_cq, 
			ep->ep_wqe,
			ep->ep_rqe,
			&filt,
			&ep->ep_qp);
	if (ret != 0) {
		goto fail;
	}
	ep->ep_qp->uq_context = ep;

	/*
	 * Allocate a memory region big enough to hold a header for each
	 * RQ entry 
	 */
	uqp = to_qpi(ep->ep_qp);
	ep->ep_hdr_ptr = calloc(uqp->uq_rq.urq_num_entries,
			sizeof(ep->ep_hdr_ptr[0]));
	if (ep->ep_hdr_ptr == NULL) {
		ret = -FI_ENOMEM;
		goto fail;
	}

	ret = usd_alloc_mr(ep->ep_domain->dom_dev,
			usd_get_recv_credits(ep->ep_qp) * USDF_HDR_BUF_ENTRY,
			&ep->ep_hdr_buf);
	if (ret != 0) {
		goto fail;
	}

	return 0;

fail:
	if (ep->ep_hdr_ptr != NULL) {
		free(ep->ep_hdr_ptr);
	}
	if (ep->ep_qp != NULL) {
		usd_destroy_qp(ep->ep_qp);
	}
	return ret;
}

static ssize_t
usdf_msg_ep_cancel(fid_t fid, void *context)
{
	return 0;
}

static struct fi_ops_ep usdf_base_msg_ops = {
	.size = sizeof(struct fi_ops_ep),
	.enable = usdf_msg_ep_enable,
	.cancel = usdf_msg_ep_cancel,
	.getopt = usdf_msg_ep_getopt,
	.setopt = usdf_msg_ep_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
};

static struct fi_ops_cm usdf_cm_msg_ops = {
	.size = sizeof(struct fi_ops_cm),
	.connect = usdf_cm_msg_connect,
	.shutdown = usdf_cm_msg_shutdown,
};

static struct fi_ops_msg usdf_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = usdf_msg_recv,
	.recvv = usdf_msg_recvv,
	.recvfrom = fi_no_msg_recvfrom,
	.recvmsg = usdf_msg_recvmsg,
	.send = usdf_msg_send,
	.sendv = usdf_msg_sendv,
	.sendto = fi_no_msg_sendto,
	.sendmsg = usdf_msg_sendmsg,
	.inject = usdf_msg_inject,
	.injectto = fi_no_msg_injectto,
	.senddata = usdf_msg_senddata,
	.senddatato = fi_no_msg_senddatato
};

static int
usdf_endpoint_open_msg(struct fid_domain *domain, struct fi_info *info,
	    struct fid_ep **ep_o, void *context)
{
	struct usdf_domain *udp;
	struct usdf_ep *ep;
	int ret;

	if ((info->caps & ~USDF_DGRAM_CAPS) != 0) {
		return -FI_EBADF;
	}

	udp = dom_ftou(domain);

	ep = calloc(1, sizeof(*ep));
	if (ep == NULL) {
		return -FI_ENOMEM;
	}

	ep->ep_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (ep->ep_sock == -1) {
		ret = -errno;
		goto fail;
	}
	if (info->src_addr != NULL) {
		if (info->addr_format == FI_SOCKADDR ||
		    info->addr_format == FI_SOCKADDR_IN) {
			ret = usdf_ep_port_bind(ep, info);
			if (ret != 0) {
				goto fail;
			}
		}
	}

	ep->ep_fid.fid.fclass = FI_CLASS_EP;
	ep->ep_fid.fid.context = context;
	ep->ep_fid.fid.ops = &usdf_ep_ops;
	ep->ep_fid.ops = &usdf_base_msg_ops;
	ep->ep_fid.cm = &usdf_cm_msg_ops;
	ep->ep_fid.msg = &usdf_msg_ops;
	ep->ep_domain = udp;
	ep->ep_caps = info->caps;
	ep->ep_mode = info->mode;
	if (info->tx_attr != NULL && info->tx_attr->size != 0) {
		ep->ep_wqe = info->tx_attr->size;
	} else {
		ep->ep_wqe = udp->dom_dev_attrs.uda_max_send_credits;
	}
	if (info->rx_attr != NULL && info->rx_attr->size != 0) {
		ep->ep_rqe = info->rx_attr->size;
	} else {
		ep->ep_rqe = udp->dom_dev_attrs.uda_max_recv_credits;
	}

	atomic_init(&ep->ep_refcnt, 0);
	atomic_inc(&udp->dom_refcnt);

	*ep_o = ep_utof(ep);
	return 0;

fail:
	if (ep != NULL) {
		if (ep->ep_sock != -1) {
			close(ep->ep_sock);
		}
		free(ep);
	}
	return ret;
}

int
usdf_endpoint_open(struct fid_domain *domain, struct fi_info *info,
	    struct fid_ep **ep_o, void *context)
{
	switch (info->ep_type) {
	case FI_EP_DGRAM:
		return usdf_endpoint_open_dgram(domain, info, ep_o, context);
	case FI_EP_MSG:
		return usdf_endpoint_open_msg(domain, info, ep_o, context);
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

int
usdf_pep_listen(struct fid_pep *fpep)
{
	struct usdf_pep *pep;
	int ret;

	pep = pep_ftou(fpep);

	ret = listen(pep->pep_sock, pep->pep_backlog);
	if (ret != 0) {
		ret = -errno;
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
		free(pep);
	}
	return ret;
}
