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

#include "usd.h"
#include "usd_post.h"

#include "usdf.h"
#include "usdf_rudp.h"
#include "usdf_rdm.h"
#include "usdf_timer.h"
#include "usdf_progress.h"

static inline void
usdf_rdm_rdc_ready(struct usdf_rdm_connection *rdc, struct usdf_tx *tx)
{
	if (!TAILQ_ON_LIST(rdc, dc_link)) {
		rdc->dc_fairness_credits = USDF_RDM_FAIRNESS_CREDITS;
		TAILQ_INSERT_TAIL(&tx->t.rdm.tx_rdc_ready, rdc, dc_link);

		/* Make sure TX is on domain ready list */
		if (!TAILQ_ON_LIST(tx, tx_link)) {
			TAILQ_INSERT_TAIL(&tx->tx_domain->dom_tx_ready,
				tx, tx_link);
		}
	}
}

static inline uint16_t
usdf_rdm_rdc_hash_helper(uint16_t *ipaddr, uint16_t port)
{
	uint16_t hash_index;

	hash_index = ipaddr[0];
	hash_index ^= ipaddr[1];
	hash_index ^= port;

	return hash_index;
}

static inline uint16_t
usdf_rdm_rdc_hash_hdr(struct rudp_pkt *pkt)
{
	return usdf_rdm_rdc_hash_helper((uint16_t *)&pkt->ip.saddr,
			pkt->udp.source);
}

static inline int
usdf_rdm_rdc_pkt_match(struct usdf_rdm_connection *rdc, struct rudp_pkt *pkt)
{
	return pkt->ip.saddr == rdc->dc_hdr.uh_ip.daddr &&
	    pkt->udp.source == rdc->dc_hdr.ud_udp.dest;
}

/*
 * Find a matching RDM connection on this domain
 */
static inline struct usdf_rdm_connection *
usdf_rdm_rdc_pkt_lookup(struct usdf_domain *udp, struct rudp_pkt *pkt)
{
	uint16_t hash_index;
	struct usdf_rdm_connection *rdc;

	hash_index = usdf_rdm_rdc_hash_hdr(pkt);

	rdc = udp->dom_rdc_hashtab[hash_index];
	while (rdc != NULL) {
		if (usdf_rdm_rdc_pkt_match(rdc, pkt)) {
			return rdc;
		}
		rdc = rdc->dc_hash_next;
	}

	return NULL;
}

/*
 * Insert rdc into domain hash table
 */
static inline void
usdf_rdm_rdc_insert(struct usdf_domain *udp, struct usdf_rdm_connection *rdc)
{
	uint16_t hash_index;

	hash_index = usdf_rdm_rdc_hash_hdr(rdc);

	rdc->dc_hash_next = udp->dom_rdc_hashtab[hash_index];
	udp->dom_rdc_hashtab[hash_index] = rdc;
}

static inline void
usdf_rdm_rdc_remove(struct usdf_domain *udp, struct usdf_rdm_connection *rdc)
{
	uint16_t hash_index;
	struct usdf_rdm_connection *prev;

	hash_index = usdf_rdm_rdc_hash_hdr(&rdc->dc_hdr);

	if (udp->dom_rdc_hashtab[hash_index] == rdc) {
		udp->dom_rdc_hashtab[hash_index] = rdc->dc_hash_next;
	} else {
		prev = udp->dom_rdc_hashtab[hash_index];
		while (prev->dc_hash_next != rdc) {
			prev = prev->dc_hash_next;
		}
		prev->dc_hash_next = rdc->dc_hash_next;
	}
}

/*
 * Get an RDM connection for this send.  If there is a connection for this
 * TX queue already attached to this destination, use that.
 * If not, check to see if one if in the connection cache (possibly put
 * there by receive).  If there is not one there either, grab a new one
 * and put it in the cache and also attch to this dest.
 */
static inline struct usdf_rdm_connection *
usdf_rdm_rdc_get(struct usdf_dest *dest, struct usdf_tx *tx)
{
	struct usdf_rdm_connection *rdc;
	struct usdf_domain *udp;

	TAILQ_FOREACH(rdc, &dest->ds_rdm_rdc_list, dc_addr_link) {
		if (rdc->dc_tx == tx) {
			return rdc;
		}
	}

	udp = tx->tx_domain;
	rdc = usdf_rdm_rdc_pkt_lookup(udp,
			&dest->ds_dest.ds_dest.ds_udp.u_hdr);
	if (rdc == NULL) {
		if (TAILQ_EMPTY(&udp->dom_rdc_free)) {
			return NULL;	// XXX alloc a new batch
		} else {
			rdc = TAILQ_FIRST(&tx->t.rdm.tx_rdc_free);
			TAILQ_REMOVE(&udp->dom_rdc_free, rdc, dc_addr_link);

			usdf_rdm_rdc_insert(udp, rdc);
			/// XXX start eviction timer
		}
	}

	/* Add to list for this dest */
	TAILQ_ADD(&dest->ds_rdm_rdc_list, rdc, dc_addr_link);
	rdc->dc_dest = dest;
	rdc->dc_tx = tx;

	return rdc;
}

/*
 * Rewind a queue entry by "rewind" packets
 */
static inline void
usdf_rdm_rewind_qe(struct usdf_rdm_qe *qe, size_t rewind, size_t mtu)
{
	size_t cur_resid;
	size_t cur_iov;
	size_t bytes;
	size_t len;

	if (qe->rd_resid == 0) {
		bytes = qe->rd_length % mtu;
		cur_resid = 0;
	} else {
		bytes = mtu;
		cur_resid = qe->rd_iov_resid;
	}
	bytes += (rewind - 1) * mtu;
	qe->rd_resid += bytes;

	cur_iov = qe->rd_cur_iov;
	while (bytes > 0) {
		len = qe->rd_iov[cur_iov].iov_len - cur_resid;
		if (len >= bytes) {
			len = bytes;
			cur_resid += len;
		} else {
			--cur_iov;
			cur_resid = 0;
		}
		bytes -= len;
	}

	qe->rd_cur_iov = cur_iov;
	qe->rd_cur_ptr = qe->rd_iov[cur_iov].iov_base +
		qe->rd_iov[cur_iov].iov_len - cur_resid;
	qe->rd_iov_resid = cur_resid;
}

/*
 * semi-native rx buffer post, i want to eventually avoid using the 
 * vnic_*() calls
 */
static inline int
_usdf_rdm_post_recv(struct usdf_rx *rx, void *buf, size_t len)
{
	struct usd_rq *rq;
	struct vnic_rq *vrq;
	struct rq_enet_desc *desc;
	struct usd_qp_impl *qp;

	qp = to_qpi(rx->rx_qp);
	rq = &qp->uq_rq;
	vrq = &rq->urq_vnic_rq;

	rq->urq_context[rq->urq_post_index] = buf;
	rq->urq_post_index = (rq->urq_post_index + 1)
		& rq->urq_post_index_mask;

	desc = vnic_rq_next_desc(vrq);
	rq_enet_desc_enc(desc, (dma_addr_t) buf,
			RQ_ENET_TYPE_ONLY_SOP, len);
	wmb();
	vnic_rq_post(vrq, buf, 0, (dma_addr_t) buf, len, 0);

	return 0;
}

/*
 * Allow external access to the inline
 */
int
usdf_rdm_post_recv(struct usdf_rx *rx, void *buf, size_t len)
{
	return _usdf_rdm_post_recv(rx, buf, len);
}

ssize_t
usdf_rdm_recv(struct fid_ep *fep, void *buf, size_t len,
		void *desc, fi_addr_t src_addr, void *context)
{
	struct usdf_ep *ep;
	struct usdf_rx *rx;
	struct usdf_rdm_qe *rqe;
	struct usdf_domain *udp;

	ep = ep_ftou(fep);
	rx = ep->ep_rx;
	udp = ep->ep_domain;

	if (TAILQ_EMPTY(&rx->r.rdm.rx_free_rqe)) {
		return -FI_EAGAIN;
	}

	pthread_spin_lock(&udp->dom_progress_lock);

	rqe = TAILQ_FIRST(&rx->r.rdm.rx_free_rqe);
	TAILQ_REMOVE(&rx->r.rdm.rx_free_rqe, rqe, rd_link);

	rqe->rd_context = context;
	rqe->rd_iov[0].iov_base = buf;
	rqe->rd_iov[0].iov_len = len;
	rqe->rd_last_iov = 0;

	rqe->rd_cur_iov = 0;
	rqe->rd_cur_ptr = buf;
	rqe->rd_iov_resid = len;
	rqe->rd_length = 0;

	TAILQ_INSERT_TAIL(&rx->r.rdm.rx_posted_rqe, rqe, rd_link);

	pthread_spin_unlock(&udp->dom_progress_lock);

	return 0;
}

ssize_t
usdf_rdm_recvv(struct fid_ep *fep, const struct iovec *iov, void **desc,
                 size_t count, fi_addr_t src_addr, void *context)
{
	return -FI_ENOSYS;
}

ssize_t
usdf_rdm_send(struct fid_ep *fep, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, void *context)
{
	struct usdf_ep *ep;
	struct usdf_tx *tx;
	struct usdf_rdm_qe *wqe;
	struct usdf_domain *udp;
	struct usdf_dest *dest;

	ep = ep_ftou(fep);
	tx = ep->ep_tx;
	udp = ep->ep_domain;
	dest = (struct usdf_dest *)dest_addr;

	if (TAILQ_EMPTY(&tx->t.rdm.tx_free_wqe)) {
		return -FI_EAGAIN;
	}

	pthread_spin_lock(&udp->dom_progress_lock);

	txd = usdf_rdm_txd_get(dest, tx);
	if (txd == NULL) {
		pthread_spin_unlock(&udp->dom_progress_lock);
		return -FI_EAGAIN;
	}

	wqe = TAILQ_FIRST(&tx->t.rdm.tx_free_wqe);
	TAILQ_REMOVE(&tx->t.rdm.tx_free_wqe, wqe, rd_link);

	wqe->rd_context = context;
	// XXX ? wqe->r.tx.rd_dest = dest;
	wqe->rd_msg_id = atomic_inc(&tx->t.rdm.tx_next_msg_id);

	wqe->rd_iov[0].iov_base = (void *)buf;
	wqe->rd_iov[0].iov_len = len;
	wqe->rd_last_iov = 0;

	wqe->rd_cur_iov = 0;
	wqe->rd_cur_ptr = buf;
	wqe->rd_iov_resid = len;
	wqe->rd_resid = len;
	wqe->rd_length = len;

	wqe->r.tx.rd_next_tx_seq = 0;

	/* add send to TX list */
	TAILQ_INSERT_TAIL(&txd->dc_wqe_posted, wqe, rd_link);
	usdf_rdm_txd_ready(txd);

	pthread_spin_unlock(&udp->dom_progress_lock);

	usdf_domain_progress(udp);

	return 0;
}

ssize_t
usdf_rdm_senddata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		uint64_t data, fi_addr_t dest_addr, void *context)
{
	return -FI_ENOSYS;
}

ssize_t
usdf_rdm_sendv(struct fid_ep *ep, const struct iovec *iov, void **desc,
                 size_t count, fi_addr_t dest_addr, void *context)
{
	return -FI_ENOSYS;
}

ssize_t
usdf_rdm_sendmsg(struct fid_ep *ep, const struct fi_msg *msg, uint64_t flags)
{
	return -FI_ENOSYS;
}

ssize_t
usdf_rdm_inject(struct fid_ep *ep, const void *buf, size_t len,
		fi_addr_t dest_addr)
{
	return -FI_ENOSYS;
}

ssize_t
usdf_rdm_recvmsg(struct fid_ep *ep, const struct fi_msg *msg, uint64_t flags)
{
	return -FI_ENOSYS;
}

/*
 * All segments send, stall this TXD until message completely ACKed
 */
static inline void
usdf_rdm_send_sent(struct usdf_tx *tx, struct usdf_rdm_connection *txd)
{
	TAILQ_REMOVE_MARK(&tx->t.rdm.tx_txd_ready, txd, dc_link);
}

static inline void
usdf_rdm_send_segment(struct usdf_tx *tx, struct usdf_rdm_connection *txd)
{
	struct rudp_pkt *hdr;
	struct usdf_rdm_qe *wqe;
	struct usd_dest *udest;
	struct usd_wq *wq;
	uint32_t index;
	size_t cur_iov;
	size_t cur_resid;
	size_t resid;
	const uint8_t *cur_ptr;
	const uint8_t *send_ptr;
	size_t sge_len;
	uint8_t *ptr;
	struct usd_wq_post_info *info;

	wqe = TAILQ_FIRST(&txd->dc_wqe_posted);
	wq = &(to_qpi(tx->tx_qp)->uq_wq);
	udest = &txd->dc_dest.ds_dest;

	index = wq->uwq_post_index;
	hdr = (struct rudp_pkt *)(wq->uwq_copybuf + index * USD_SEND_MAX_COPY);

	memcpy(hdr, &udest->ds_dest.ds_udp.u_hdr, sizeof(struct usd_udp_hdr));

	resid = wqe->rd_resid;
	cur_iov = wqe->rd_cur_iov;
	cur_ptr = wqe->rd_cur_ptr;
	cur_resid = wqe->rd_iov_resid;

	if (resid < USD_SEND_MAX_COPY - sizeof(*hdr)) {
		hdr->p.rdm.opcode = htons(RUDP_OP_LAST);
		hdr->p.rdm.r.rdm_data.length = htons(resid);
		hdr->p.rdm.r.rdm_data.seqno = htons(wqe->r.tx.rd_tx_next_seq);
		++wqe->r.tx.rd_tx_next_seq;

		ptr = (uint8_t *)(hdr + 1);
		while (resid > 0) {
			memcpy(ptr, cur_ptr, cur_resid);
			ptr += wqe->rd_iov_resid;
			resid -= wqe->rd_iov_resid;
			++cur_iov;
			cur_ptr = wqe->rd_iov[cur_iov].iov_base;
			cur_resid = wqe->rd_iov[cur_iov].iov_len;
		}

		/* add packet lengths */
		sge_len = resid;
		hdr->ip.tot_len = htons(
				sge_len + sizeof(struct rudp_pkt) -
				sizeof(struct ether_header));
		hdr->udp.len = htons(
				(sizeof(struct rudp_pkt) -
				 sizeof(struct ether_header) -
				 sizeof(struct iphdr)) + sge_len);

		index = _usd_post_send_one(wq, hdr,
				resid + sizeof(*hdr), 1);
	} else {
		struct vnic_wq *vwq;
		u_int8_t offload_mode = 0, eop;
		u_int16_t mss = 7, header_length = 0, vlan_tag = 0;
		u_int8_t vlan_tag_insert = 0, loopback = 0, fcoe_encap = 0;
		struct wq_enet_desc *desc;
		size_t space;
		size_t num_sge;
		size_t sent;

		vwq = &wq->uwq_vnic_wq;
		desc = wq->uwq_next_desc;
		space = tx->tx_domain->dom_fabric->fab_dev_attrs->uda_mtu -
			sizeof(*hdr);
		num_sge = 1;

		/* encode header desc */
		eop = 0;
		wq_enet_desc_enc(desc, (uintptr_t)hdr, sizeof(*hdr),
			mss, header_length, offload_mode, eop, 0, fcoe_encap,
			vlan_tag_insert, vlan_tag, loopback);
		
		do {
			desc = (struct wq_enet_desc *)
				((uintptr_t)wq->uwq_desc_ring + (index << 4));
			index = (index + 1) & wq->uwq_post_index_mask;

			send_ptr = cur_ptr;
			if (cur_resid >= space) {
				sge_len = space;
				eop = 1;
				cur_resid -= sge_len;
				cur_ptr += sge_len;
			} else {
				sge_len = cur_resid;
				if (num_sge == USDF_RDM_MAX_SGE - 1 ||
				    cur_resid == resid) {
					eop = 1;
				}
				++cur_iov;
				cur_ptr = wqe->rd_iov[cur_iov].iov_base;
				cur_resid = wqe->rd_iov[cur_iov].iov_len;
			}

			wq_enet_desc_enc(desc, (uintptr_t)send_ptr, sge_len,
				mss, header_length, offload_mode, eop, eop,
				fcoe_encap, vlan_tag_insert,
				vlan_tag, loopback);

			++num_sge;
			space -= sge_len;
			resid -= sge_len;
		} while (space > 0 && num_sge <= USDF_RDM_MAX_SGE && resid > 0);

		/* add packet lengths */
		sent = tx->tx_domain->dom_fabric->fab_dev_attrs->uda_mtu -
			space;
		hdr->ip.tot_len = htons(
				sent + sizeof(struct rudp_pkt) -
				sizeof(struct ether_header));
		hdr->udp.len = htons(
				(sizeof(struct rudp_pkt) -
				 sizeof(struct ether_header) -
				 sizeof(struct iphdr)) + sent);
if (0) {
if ((random() % 177) == 0 && resid == 0) {
	hdr->eth.ether_type = 0;
//printf("BORK seq %u\n", wqe->r.tx.rd_tx_next_seq);
}
}

		if (resid == 0) {
			hdr->p.rdm.opcode = htons(RUDP_OP_LAST);
		} else {
			hdr->p.rdm.opcode = htons(RUDP_OP_FIRST);
		}
		hdr->rdm.r.rc_data.length = htons(sent);
		hdr->p.rdm.msg_id = wqe->rd_msg_id_be;
		hdr->p.rdm.r.rdm_data.seqno = htons(wqe->r.tx.rd_tx_next_seq);
		++wqe->r.tx.rd_tx_next_seq;
					
		wmb();
		iowrite64(index, &vwq->ctrl->posted_index);

		wq->uwq_next_desc = (struct wq_enet_desc *)
		 ((uintptr_t)wq->uwq_desc_ring + (index << 4));
		wq->uwq_post_index = (index + 1) & wq->uwq_post_index_mask;
		wq->uwq_send_credits -= num_sge;
	}

	info = &wq->uwq_post_info[index];
	info->wp_context = tx;
	info->wp_len = sge_len;

	/* If send complete, wait for last ack on this message */
	if (resid == 0) {
		usdf_rdm_send_sent(tx, txd);
	} else {
		wqe->rd_resid = resid;
		wqe->rd_iov_resid = cur_resid;
		wqe->rd_cur_iov = cur_iov;
		wqe->rd_cur_ptr = cur_ptr;
	}

	/* set ack timer */
	usdf_timer_set(tx->tx_domain->dom_fabric, txd->dc_ack_timer,
			USDF_RUDP_ACK_TIMEOUT);
}

static inline void
usdf_rdm_send_ack(struct usdf_tx *tx, struct usdf_rdm_qe *rqe)
{
	struct rudp_pkt *hdr;
	struct usdf_rdm_qe *rqe;
	struct usd_wq *wq;
	uint32_t last_post;
	struct usd_wq_post_info *info;
	uint16_t seq;

	wq = &(to_qpi(tx->tx_qp)->uq_wq);
	hdr = (struct rudp_pkt *) (wq->uwq_copybuf +
			wq->uwq_post_index * USD_SEND_MAX_COPY);

	memcpy(hdr, &rqe->r.rx.rd_hdr, sizeof(struct usd_udp_hdr));

	if (ep->e.rdm.ep_send_nak) {
		hdr->p.rdm.opcode = htons(RUDP_OP_NAK);
		seq = ep->e.rdm.ep_next_rx_seq;
		hdr->p.rdm.r.nak.nak_seq = htons(seq);
		ep->e.rdm.ep_send_nak = 0;
	} else {
		hdr->p.rdm.opcode = htons(RUDP_OP_ACK);
		seq = ep->e.rdm.ep_next_rx_seq - 1;
		hdr->p.rdm.r.ack.ack_seq = htons(seq);
	}

	/* add packet lengths */
	hdr->ip.tot_len = htons(
			sizeof(struct rudp_pkt) -
			sizeof(struct ether_header));
	hdr->udp.len = htons(sizeof(struct rudp_pkt) -
			 sizeof(struct ether_header) - sizeof(struct iphdr));

	last_post = _usd_post_send_one(wq, hdr, sizeof(*hdr), 1);

	info = &wq->uwq_post_info[last_post];
	info->wp_context = tx;
	info->wp_len = 0;
}

/*
 * If this TX has sends to do and is not on domain ready list, then
 * this completion means we can go back on the domain ready list
 */
static void
usdf_rdm_send_completion(struct usd_completion *comp)
{
	struct usdf_tx *tx;

	tx = comp->uc_context;

	if (!TAILQ_EMPTY(&tx->t.rdm.tx_txd_ready) &&
	    !TAILQ_ON_LIST(tx, tx_link)) {
		TAILQ_INSERT_TAIL(&tx->tx_domain->dom_tx_ready, tx, tx_link);
	}
}

/*
 * Keep progressing sends on this queue until:
 * a) no more send credits on the queue (it's full)
 * or
 * b) all endpoints are complete or blocked awaiting ACKs
 */
void
usdf_rdm_tx_progress(struct usdf_tx *tx)
{
	struct usdf_rdm_qe *wqe;
	struct usdf_rdm_qe *rqe;
	struct usd_qp_impl *qp;

	qp = to_qpi(tx->tx_qp);
	while (qp->uq_wq.uwq_send_credits > 1 &&
			!TAILQ_EMPTY(&tx->t.rdm.tx_ep_have_acks)) {
		rqe = TAILQ_FIRST(&tx->t.rdm.tx_qe_have_acks);
		TAILQ_REMOVE_MARK(&tx->t.rdm.tx_qe_have_acks,
				rqe, r.tx.rd_ack_link);

		usdf_rdm_send_ack(tx, rqe);
	}

	while (qp->uq_wq.uwq_send_credits > 1 &&
			!TAILQ_EMPTY(&tx->t.rdm.tx_txd_ready)) {
		txd = TAILQ_FIRST(&tx->t.rdm.tx_txd_ready);

		/*
		 * Send next segment on this TXD. This will also remove this
		 * TXD from the TX ready list if it completes or stalls.
		 */
		usdf_rdm_send_segment(tx, txd);

		--txd->dc_seq_credits;
		if (TAILQ_EMPTY(&txd->dc_wqe_posted)) {
			TAILQ_REMOVE_MARK(&tx->t.msg.tx_txd_ready,
					txd, dc_link);
		} else {
			--txd->dc_fairness_credits;
			if (txd->dc_seq_credits == 0) {
				TAILQ_REMOVE_MARK(&tx->t.msg.tx_txd_ready,
					txd, dc_link);
				txd->dc_fairness_credits =
					USDF_rdm_FAIRNESS_CREDITS;

			/* fairness credits exhausted, go to back of the line */
			} else if (txd->dc_fairness_credits == 0) {
				TAILQ_REMOVE(&tx->t.msg.tx_txd_ready,
					txd, dc_link);
				TAILQ_INSERT_TAIL(&tx->t.msg.tx_txd_ready,
					txd, dc_link);
				txd->dc_fairness_credits =
					USDF_rdm_FAIRNESS_CREDITS;
			}
		}
	}
}

static inline uint16_t
usdf_rdm_rqe_hash_helper(uint16_t *ipaddr, uint16_t port, uint16_t *msg_id)
{
	uint16_t hash_index;

	hash_index = ipaddr[0];
	hash_index ^= ipaddr[1];
	hash_index ^= port;
	hash_index ^= msg_id[0];
	hash_index ^= msg_id[1];

	return hash_index;
}

static inline uint16_t
usdf_rdm_rqe_hash_rqe(struct usdf_rdm_qe *rqe)
{
	return usdf_rdm_rqe_hash_helper((uint16_t *)&rqe->r.rx.rd_ipaddr_be),
	       rqe->r.rx.rd_port_be, rqe->rd_msg_id_be);
}

static inline uint16_t
usdf_rdm_rqe_hash_pkt(struct rudp_pkt *pkt)
{
	return usdf_rdm_rqe_hash_helper((uint16_t *)&pkt->ip.saddr,
			pkt->udp.source,
			(uint16_t *)&pkt->p.rdm.msg_id);
}

static inline int
usdf_rdm_rqe_pkt_match(struct usdf_rdm_qe *rqe, struct rudp_pkt *pkt)
{
	return pkt->ip.saddr == rqe->r.rx.rd_ipaddr_be &&
	    pkt->udp.source == rqe->r.rx.rd_port_be &&
	    pkt->p.rd.msg_id == rqe->rd_msg_id_be;
}

/*
 * Find a matching WQE on this domain
 */
static inline struct usdf_rdm_qe *
usdf_rdm_rqe_lookup(struct usdf_domain *udp, struct rudp_pkt *pkt)
{
	uint16_t hash_index;
	struct usdf_rdm_qe *rqe;

	hash_index = usdf_rdm_rqe_hash_pkt(pkt);

	rqe = udp->dom_rqe_hashtab[hash_index];
	while (rqe != NULL) {
		if (usdf_rdm_rqe_pkt_match(rqe, pkt)) {
			return rqe;
		}
		rqe = rqe->r.rx.rd_hash_next;
	}

	return NULL;
}

/*
 * Insert rqe into domain hash table
 */
static inline void
usdf_rdm_rqe_insert(struct usdf_domain *udp, struct usdf_rdm_qe *rqe)
{
	uint16_t hash_index;

	hash_index = usdf_rdm_rqe_hash_rqe(rqe);

	rqe->r.rx.rd_hash_next = udp->dom_rqe_hashtab[hash_index];
	udp->dom_rqe_hashtab[hash_index] = rqe;
}

static inline void
usdf_rdm_rqe_remove(struct usdf_domain *udp, struct usdf_rdm_qe *rqe)
{
	uint16_t hash_index;
	struct usdf_rdm_qe *prev;

	hash_index = usdf_rdm_rqe_hash_rqe(rqe);

	if (udp->dom_rqe_hashtab[hash_index] == rqe) {
		udp->dom_rqe_hashtab[hash_index] = rqe->r.rx.rd_hash_next;
	} else {
		prev = udp->dom_rqe_hashtab[hash_index];
		while (prev->r.rx.rd_hash_next != rqe) {
			prev = prev->r.rx.rd_hash_next;
		}
		prev->r.rx.rd_hash_next = rqe->r.rx.rd_hash_next;
	}
}

static void inline
usdf_rdm_recv_complete(struct usdf_rx *rx, struct usdf_rdm_qe *rqe)
{
	struct usdf_cq_hard *hcq;

	hcq = rx->r.rdm.rx_hcq;
	hcq->cqh_post(hcq, rqe->rd_context, rqe->rd_length);

	/* remove from hash, but this only goes back on free list
	 * after last ACK has been sent
	 */
	usdf_rdm_rqe_remove(rx->rx_domain, rqe);
}

static inline void
usdf_rdm_wqe_has_ack(struct usdf_rdm_qe *wqe)
{
	struct usdf_tx *tx;
	struct usdf_domain *udp;

	if (!TAILQ_ON_LIST(wqe, r.tx.rd_ack_link)) {
		tx = wqe->rd_tx;
		udp = tx->tx_domain;
		TAILQ_INSERT_TAIL(&tx->t.rdm.tx_wqe_have_acks, wqe,
				r.tx.rd_ack_link);
		/* Add TX to domain list if not present */
		if (!TAILQ_ON_LIST(tx, tx_link)) {
			TAILQ_INSERT_TAIL(&udp->dom_tx_ready, tx, tx_link);
		}
	}
}

static inline int
usdf_rdm_check_seq(struct usdf_rdm_qe *rqe, struct rudp_pkt *pkt)
{
	uint16_t seq;
	int ret;

	seq = ntohs(pkt->msg.m.rc_data.seqno);

	/* Drop bad seq, send NAK if seq from the future */
	if (seq != rqe->r.rx.rd_next_rx_seq) {
		if (RUDP_SEQ_GT(seq, rqe->r.rx.rd_next_rx_seq)) {
			rqe->r.rx.rd_send_nak = 1;
		}
		ret = -1;
	} else {
		++rqe->r.rx.rd_next_rx_seq;
		ret = 0;
	}
	usdf_rdm_rqe_has_ack(rqe);

	return ret;
}

static inline void
usdf_rdm_process_ack(struct usdf_rdm_qe *wqe, uint16_t seq)
{
	struct usdf_cq_hard *hcq;
	struct usdf_fabric *fp;
	struct usdf_tx *tx;
	uint16_t max_ack;
	unsigned credits;

	/* don't try to ACK what we don't think we've sent */
	max_ack = wqe->r.tx.rd_next_tx_seq - 1;
	if (RUDP_SEQ_GT(seq, max_ack)) {
		seq = max_ack;
	}

	hcq = wqe->rd_tx->t.rdm.tx_hcq;
	while (!TAILQ_EMPTY(&wqe->r.rx.rd_sent_wqe)) {
		wqe = TAILQ_FIRST(&wqe->r.rx.rd_sent_wqe);
		if (RUDP_SEQ_LE(wqe->rd_last_seq, seq)) {
			TAILQ_REMOVE(&wqe->r.rx.rd_sent_wqe, wqe, rd_link);
			hcq->cqh_post(hcq, wqe->rd_context, wqe->rd_length);

			TAILQ_INSERT_HEAD(&wqe->ep_tx->t.rdm.tx_free_wqe,
					wqe, rd_link);
		} else {
			break;
		}
	}

	credits = RUDP_SEQ_DIFF(seq, wqe->r.rx.rd_last_rx_ack);
	if (wqe->r.rx.rd_seq_credits == 0 && credits > 0 &&
			!TAILQ_EMPTY(&wqe->r.rx.rd_posted_wqe)) {
		usdf_rdm_ep_ready(ep);
	}
	wqe->r.rx.rd_seq_credits += credits;
	wqe->r.rx.rd_last_rx_ack = seq;

	/* If all ACKed, cancel timer, else reset it */
	fp = wqe->rd_tx->tx_domain->dom_fabric;
	if (seq == max_ack) {
		usdf_timer_cancel(fp, wqe->r.rx.rd_ack_timer);
	} else {
		usdf_timer_reset(fp, wqe->r.rx.rd_ack_timer,
				USDF_RUDP_ACK_TIMEOUT);
	}
}

static inline void
usdf_rdm_process_nak(struct usdf_rdm_connection *txd, uint16_t seq)
{
	struct usdf_rdm_qe *wqe;
	struct usdf_fabric *fp;
	size_t rewind;

	if (TAILQ_EMPTY(&txd->dc_wqe_posted)) {
		return;
	}

	wqe = TAILQ_FIRST(&txd->dc_wqe_posted);

	/* Ignore NAKs of future packets */
	if (RUDP_SEQ_GE(seq, wqe->r.tx.rd_next_rx_seq)) {
		return;
	}

	/* reset WQE to old sequence # */
	rewind = RUDP_SEQ_DIFF(wqe->r.tx.rd_next_tx_seq, seq);
	if (rewind > 0) {
		txd->dc_seq_credits = USDF_RUDP_SEQ_CREDITS;
		wqe->r.tx.rd_next_tx_seq = seq;

		fp = txd->dc_tx->tx_domain->dom_fabric;
		usdf_rdm_rewind_qe(wqe, rewind,
			fp->fab_dev_attrs->uda_mtu - sizeof(struct rudp_pkt));

		usdf_rdm_txd_ready(txd);
	}
}

void
usdf_rdm_txd_timeout(void *vtxd)
{
	struct usdf_rdm_connection *txd;
	struct usdf_rdm_qe *wqe;
	struct usdf_domain *udp;
	uint16_t nak;

	txd = vtxd;
	udp = txd->dc_tx->tx_domain;

	pthread_spin_lock(&udp->dom_progress_lock);
	if (TAILQ_EMPTY(&txd->dc_wqe_posted)) {
		goto done;
	}
	wqe = TAILQ_FIRST(&txd->dc_wqe_posted);
	nak = wqe->r.tx.rd_last_rx_ack + 1;

	usdf_rdm_process_nak(txd, nak);
done:
	pthread_spin_unlock(&udp->dom_progress_lock);
}

static inline void
usdf_rdm_rx_ack(struct usdf_rx *rx, struct rudp_pkt *pkt)
{
	uint16_t seq;
	struct usdf_rdm_connection *txd;

	txd = usdf_rdm_txd_lookup(rx->rx_domain, pkt);
	seq = ntohs(pkt->p.rdm.r.nak.nak_seq);
	usdf_rdm_process_ack(txd, seq);
}

static inline void
usdf_rdm_rx_nak(struct usdf_rx *rx, struct rudp_pkt *pkt)
{
	uint16_t seq;
	struct usdf_rdm_connection *txd;

	txd = usdf_rdm_txd_lookup(rx->rx_domain, pkt);
	seq = ntohs(pkt->p.rdm.r.nak.nak_seq);
	usdf_rdm_process_ack(txd, seq);

	usdf_rdm_process_nak(txd, seq);
}

/*
 * Handle a receive on a queue servicing a message endpoint
 */
static inline void
usdf_rdm_handle_recv(struct usdf_domain *udp, struct usd_completion *comp)
{
	struct rudp_pkt *pkt;
	struct usdf_rdm_qe *rqe;
	struct usd_qp *qp;
	struct usdf_rx *rx;
	uint32_t opcode;
	uint8_t *rx_ptr;
	uint8_t *rqe_ptr;
	size_t cur_iov;
	size_t iov_resid;
	size_t rxlen;
	size_t copylen;
	int ret;

	rx = qp->uq_context;
	pkt = comp->uc_context;
	opcode = ntohs(pkt->p.rdm.opcode);

	switch (opcode) {
	case RUDP_OP_ACK:
		usdf_rdm_rx_ack(rx, pkt);
		goto repost;

	case RUDP_OP_NAK:
		usdf_rdm_rx_nak(rx, pkt);
		goto repost;
	default:
		break;
	}

	if ((opcode & ~RUDP_OP_DATA_MASK) != 0) {
		goto repost;
	}

	/* Find RQE for this pkt */
	if (opcode & RUDP_OP_FIRST) {
		if (TAILQ_EMPTY(rx->r.rdm.rx_posted_rqe)) {
			goto repost;
		}
		rqe = TAILQ_FIRST(&rx->r.rdm.rx_posted_rqe);

		/* fabricate return header */
		memcpy(rqe->r.rx.rd_hdr.uh_eth.ether_dhost,
			pkt->ether->ether_shost, ETH_ALEN);
		memcpy(rqe->r.rx.rd_hdr.uh_eth.ether_shost,
			pkt->ether->ether_dhost, ETH_ALEN);
		rqe->r.rx.rd_hdr.uh_ip.daddr = pkt->ip.saddr;
		rqe->r.rx.rd_hdr.uh_ip.saddr = pkt->ip.daddr;
		rqe->r.rx.rd_hdr.uh_udp.dest = pkt->udp.source;
		rqe->r.rx.rd_hdr.uh_udp.source = pkt->udp.dest;

		/* add to RX hash table */
		usdf_rdm_rqe_insert(udp, rqe);
	
	} else {
		rqe = usdf_rdm_rqe_lookup(udp, pkt);
		if (rqe == NULL) {
			goto repost;
		}

		ret = usdf_rdm_check_seq(rqe, pkt);
		if (ret == -1) {
			goto repost;
		}
	}

	/* Consume the data in the packet */
	rxlen = ntohs(pkt->msg.m.rc_data.length);
	rqe->rd_length += rxlen;

	rx_ptr = (uint8_t *)(pkt + 1);
	rqe_ptr = (uint8_t *)rqe->rd_cur_ptr;
	iov_resid = rqe->rd_iov_resid;
	cur_iov = rqe->rd_cur_iov;
	while (rxlen > 0) {
		copylen = MIN(rxlen, iov_resid);
		memcpy(rqe_ptr, rx_ptr, copylen);
		rx_ptr += copylen;
		rxlen -= copylen;
		iov_resid -= copylen;
		if (iov_resid == 0) {
			if (cur_iov == rqe->rd_last_iov) {
				break;
			}
			++cur_iov;
			rqe_ptr = rqe->rd_iov[cur_iov].iov_base;
			iov_resid = rqe->rd_iov[cur_iov].iov_len;
		} else {
			rqe_ptr += copylen;
		}
	}

	if (rxlen > 0) {
		rqe->rd_length -= rxlen;
/* printf("RQE truncated XXX\n"); */
	} else if (opcode & RUDP_OP_LAST) {
		usdf_rdm_recv_complete(rx, rqe);
	}

repost:
	/* repost buffer */
	_usdf_rdm_post_recv(rx, pkt,
			rx->rx_domain->dom_fabric->fab_dev_attrs->uda_mtu);
}

/*
 * Process message completions
 */
void
usdf_rdm_hcq_progress(struct usdf_cq_hard *hcq)
{
	struct usd_completion comp;

	while (usd_poll_cq(hcq->cqh_ucq, &comp) != -EAGAIN) {
		switch (comp.uc_type) {
		case USD_COMPTYPE_SEND:
			usdf_rdm_send_completion(&comp);
			break;
		case USD_COMPTYPE_RECV:
			usdf_rdm_handle_recv(hcq->cqh_cq->cq_domain, &comp);
			break;
		}
	}
}
