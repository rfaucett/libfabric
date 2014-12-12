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
#ifndef _USDF_RDM_H_
#define _USDF_RDM_H_

#define USDF_RDM_CAPS (FI_MSG | FI_SOURCE | FI_SEND | FI_RECV)

#define USDF_RDM_SUPP_MODE (FI_LOCAL_MR)
#define USDF_RDM_REQ_MODE (FI_LOCAL_MR)

#define USDF_RDM_MAX_SGE 8
#define USDF_RDM_DFLT_SGE 8
#define USDF_RDM_MAX_CTX_SIZE 1024
#define USDF_RDM_DFLT_CTX_SIZE 128

#define USDF_RDM_MAX_MSG UINT_MAX

#define USDF_RDM_FAIRNESS_CREDITS 16

#define USDF_RDM_RUDP_SEQ_CREDITS 256

struct usdf_rdm_qe {
	void *rd_context;
	uint32_t rd_msg_id_be;
	struct usdf_tx *rd_tx;

	struct iovec rd_iov[USDF_RDM_MAX_SGE];
	size_t rd_last_iov;
	size_t rd_length;

	size_t rd_cur_iov;
	const uint8_t *rd_cur_ptr;
	size_t rd_resid;      	/* amount remaining in entire rdm */
	size_t rd_iov_resid;    /* amount remaining in current iov */

	TAILQ_ENTRY(usdf_rdm_qe) rd_link;

	union {
		struct {
			struct usd_dest *rd_dest;
			uint16_t rd_next_tx_seq;
			TAILQ_ENTRY(usdf_rdm_qe) rd_ack_link;
		} tx;
		struct {
			uint32_t rd_ipaddr_be;
			uint16_r rd_port_be;
			uint16_t rd_next_rx_seq;

			struct usdf_rdm_qe *rd_hash_link;
		} rx;
	}r;
};

int usdf_rdm_post_recv(struct usdf_rx *rx, void *buf, size_t len);
int usdf_rdm_fill_tx_attr(struct fi_tx_attr *txattr);
int usdf_rdm_fill_rx_attr(struct fi_rx_attr *rxattr);
int usdf_cq_rdm_poll(struct usd_cq *ucq, struct usd_completion *comp);
void usdf_rdm_ep_timeout(void *vep);

void usdf_rdm_hcq_progress(struct usdf_cq_hard *hcq);
void usdf_rdm_tx_progress(struct usdf_tx *tx);

/* fi_ops_cm for RC */
int usdf_cm_rdm_connect(struct fid_ep *ep, const void *addr,
	const void *param, size_t paramlen);
int usdf_cm_rdm_accept(struct fid_ep *fep, const void *param, size_t paramlen);
int usdf_cm_rdm_shutdown(struct fid_ep *ep, uint64_t flags);

/* fi_ops_rdm for RC */
ssize_t usdf_rdm_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
	fi_addr_t src_addr, void *context);
ssize_t usdf_rdm_recvv(struct fid_ep *ep, const struct iovec *iov,
	void **desc, size_t count, fi_addr_t src_addr, void *context);
ssize_t usdf_rdm_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
	uint64_t flags);

ssize_t usdf_rdm_send(struct fid_ep *ep, const void *buf, size_t len,
	void *desc, fi_addr_t src_addr, void *context);
ssize_t usdf_rdm_sendv(struct fid_ep *ep, const struct iovec *iov,
	void **desc, size_t count, fi_addr_t src_addr, void *context);
ssize_t usdf_rdm_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
	uint64_t flags);
ssize_t usdf_rdm_senddata(struct fid_ep *ep, const void *buf, size_t len,
	void *desc, uint64_t data, fi_addr_t src_addr, void *context);

ssize_t usdf_rdm_inject(struct fid_ep *ep, const void *buf, size_t len,
	fi_addr_t src_addr);
	


#endif /* _USDF_RDM_H_ */
