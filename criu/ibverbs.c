#include <infiniband/verbs.h>
#include <rdma/rdma_user_rxe.h>

#include "files.h"
#include "fdinfo.h"
#include "files-reg.h"
#include "imgset.h"
#include "ibverbs.h"
#include "mem.h"
#include "restorer.h"
#include "rst-malloc.h"

#include "protobuf.h"
#include "images/ibverbs.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "ibverbs: "

static LIST_HEAD(ibverbs_restore_objects);

struct ibverbs_list_entry {
	struct list_head	restore_list;
	struct ibv_device	*ibdev;
	struct ibv_context	*ibcontext;
	IbverbsObject		*obj;
	int 			(*restore)(struct ibverbs_list_entry *entry, struct task_restore_args *ta);
};

static int num_dev;
static struct ibv_device **dev_list = NULL;

static struct ibv_context *IBCONTEXT;
static int *ibverbs_contexts = NULL;
static int ibverbs_contexts_n = 0;

static int append_context(int context_fd)
{
	ibverbs_contexts_n++;
	ibverbs_contexts = xrealloc(ibverbs_contexts, ibverbs_contexts_n * sizeof(*ibverbs_contexts));
	if (!ibverbs_contexts) {
		return -1;
	}

	ibverbs_contexts[ibverbs_contexts_n - 1] = context_fd;

	return 0;
}

static int prepare_contexts(struct task_restore_args *ta)
{
	ta->ibverbs_contexts = (int *)rst_mem_align_cpos(RM_PRIVATE);
	ta->ibverbs_contexts_n = ibverbs_contexts_n;

	int *rcontexts;
	unsigned long size = sizeof(*rcontexts) * ibverbs_contexts_n;
	rcontexts = rst_mem_alloc(size, RM_PRIVATE);
	if (!rcontexts) {
		return -1;
	}

	memcpy(rcontexts, ibverbs_contexts, sizeof(*rcontexts) * ibverbs_contexts_n);

	return 0;
}

static int install_rxe_service()
{
	int fd;
	int ret;
        const char *last_qpn_path = "/proc/sys/net/rdma_rxe/last_qpn";
        const char *last_mrn_path = "/proc/sys/net/rdma_rxe/last_mrn";

        fd = open(last_qpn_path, O_RDWR);
	if (fd < 0) {
		pr_err("Failed to open %s: %s", last_qpn_path, strerror(errno));
		return -1;
	}

        ret = install_service_fd(CR_IBVERBS_RXE_QPN, fd);
        if (ret < 0) {
		pr_err("Failed to install QPN service fd");
		return -1;
	}

        fd = open(last_mrn_path, O_RDWR);
        if (fd < 0) {
          pr_err("Failed to open %s: %s", last_mrn_path, strerror(errno));
          return -1;
        }

        ret = install_service_fd(CR_IBVERBS_RXE_MRN, fd);
        if (ret < 0) {
          pr_err("Failed to install QPN service fd");
          return -1;
        }

        return 0;
}

int init_ibverbs()
{
	dev_list = ibv_get_device_list(&num_dev);

	if (num_dev <= 0) {
		pr_err(" Did not detect devices. If device exists, check if driver is up.\n");
		return -1;
	}

	return install_rxe_service();
}

static struct ibv_device* find_ibdev(const char *ib_devname)
{
	if (!dev_list) {
		if (init_ibverbs())
			return NULL;
	}

	struct ibv_device *ib_dev = NULL;

	if (!ib_devname) {
		ib_dev = dev_list[0];
		if (!ib_dev) {
			pr_err("No IB devices found\n");
			return NULL;
		}
	} else {
		for (; (ib_dev = *dev_list); ++dev_list)
			if (!strcmp(ibv_get_device_name(ib_dev), ib_devname))
				break;
		if (!ib_dev)
			return NULL;
	}
	return ib_dev;
}

/* Ibverbs driver related functions */

struct ibverbs_driver {
	short type;
	char *name;
};

static struct ibverbs_driver rxe_driver = {
	.type			= IBVERBS_TYPE__RXE,
	.name			= "rxe",
};

struct ibverbs_driver *get_ibverbs_driver(dev_t rdev, dev_t dev)
{
	int major, minor;

	major = major(rdev);
	minor = minor(rdev);

	switch (major) {
	case 231:
		if (minor == 192)
			return &rxe_driver;
		break;
	}

	return NULL;
}

struct ibverbs_file_info {
	IbverbsEntry		*ibv;
	struct file_desc	d;
};

static void pr_info_ibverbs(char *action, IbverbsEntry *ibv)
{
	pr_info("IB verbs %s: id %#08x flags %#04x\n", action, ibv->id, ibv->flags);
}

static IbverbsQueue *pballoc_queue()
{
	IbverbsQueue *queue = NULL;
	RxeQueue *rxe = NULL;

	queue = xmalloc(sizeof(*queue));
	rxe = xmalloc(sizeof(*rxe));

	if (!queue || !rxe) {
		xfree(queue);
		xfree(rxe);
		return NULL;
	}

	ibverbs_queue__init(queue);
	rxe_queue__init(rxe);

	queue->rxe = rxe;

	return queue;
}

static void save_rxe_queue(IbverbsQueue *rq, struct rxe_dump_queue *dump_queue)
{
	rq->start = dump_queue->start;
	rq->size = dump_queue->size;
	rq->rxe->log2_elem_size = dump_queue->log2_elem_size;
	rq->rxe->index_mask = dump_queue->index_mask;
	rq->rxe->producer_index = dump_queue->producer_index;
	rq->rxe->consumer_index = dump_queue->consumer_index;
}

static void restore_rxe_queue(struct rxe_dump_queue *dump_queue, IbverbsQueue *rq)
{
	dump_queue->start = rq->start;
	dump_queue->size = rq->size;
	dump_queue->log2_elem_size = rq->rxe->log2_elem_size;
	dump_queue->index_mask = rq->rxe->index_mask;
	dump_queue->producer_index = rq->rxe->producer_index;
	dump_queue->consumer_index = rq->rxe->consumer_index;
}

static int dump_one_ibverbs_pd(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_pd *dump_pd;
	IbverbsPd *pd;

	dump_pd = container_of(dump_obj, struct ib_uverbs_dump_object_pd, obj);

	pr_debug("Found object PD: %d\n", dump_pd->obj.handle);

	if (dump_obj->size != sizeof(*dump_pd)) {
		pr_err("Unmatched object size: %d expected %ld\n", dump_obj->size, sizeof(*dump_pd));
		return -1;
	}

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		return -1;
	}
	ibverbs_object__init(*pb_obj);
	pd = xmalloc(sizeof(*pd));
	if (!pd) {
		xfree(*pb_obj);
		return -1;
	}
	ibverbs_pd__init(pd);

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__PD;
	(*pb_obj)->handle = dump_pd->obj.handle;
	(*pb_obj)->pd = pd;

	return sizeof(*dump_pd);
}

static int dump_one_ibverbs_comp_channel(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_comp_channel *dump_comp_channel;
	IbverbsCompChannel *comp_channel;

	dump_comp_channel = container_of(dump_obj, struct ib_uverbs_dump_object_comp_channel, obj);

	pr_debug("Found object COMP_CHANNEL: %d\n", dump_comp_channel->obj.handle);

	if (dump_obj->size != sizeof(*dump_comp_channel)) {
		pr_err("Unmatched object size: %d expected %ld\n", dump_obj->size, sizeof(*dump_comp_channel));
		return -1;
	}

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		return -1;
	}
	ibverbs_object__init(*pb_obj);
	comp_channel = xmalloc(sizeof(*comp_channel));
	if (!comp_channel) {
		xfree(*pb_obj);
		return -1;
	}
	ibverbs_comp_channel__init(comp_channel);

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__COMP_CHANNEL;
	(*pb_obj)->handle = dump_comp_channel->obj.handle;
	(*pb_obj)->comp_channel = comp_channel;

	return sizeof(*dump_comp_channel);
}

static int dump_one_ibverbs_mr(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj,
			       struct vm_area_list *vmas)
{
	struct ib_uverbs_dump_object_mr *dump_mr;
	IbverbsMr *mr;

	dump_mr = container_of(dump_obj, struct ib_uverbs_dump_object_mr, obj);
	pr_debug("Found object MR: %d @0x%llx + 0x%llx\n", dump_mr->obj.handle,
		 dump_mr->address, dump_mr->length);

	if (dump_obj->size != sizeof(*dump_mr)) {
		pr_err("Unmatched object size: %d expected %ld\n", dump_obj->size, sizeof(*dump_mr));
		return -1;
	}

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		return -1;
	}
	ibverbs_object__init(*pb_obj);
	mr = xmalloc(sizeof(*mr));
	if (!mr) {
		xfree(*pb_obj);
		return -1;
	}
	ibverbs_mr__init(mr);

	mr->address = dump_mr->address;
	mr->length = dump_mr->length;
	mr->access = dump_mr->access;
	mr->pd_handle = dump_mr->pd_handle;
	mr->lkey = dump_mr->lkey;
	mr->rkey = dump_mr->rkey;
	mr->mrn = dump_mr->rxe.mrn;

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__MR;
	(*pb_obj)->handle = dump_mr->obj.handle;
	(*pb_obj)->mr = mr;

	struct vma_area *vma, *p;
	list_for_each_entry_safe(vma, p, &vmas->h, list) {
		if ((vma->e->end - 1 < mr->address) ||
		    (mr->address + mr->length - 1 < vma->e->start)) {
			/* No overlap. */
			continue;
		}

		vma->e->status |= VMA_AREA_IBVERBS;
	}

	return sizeof(*dump_mr);

}

static int dump_one_ibverbs_cq(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_cq *dump_cq;
	IbverbsCq *cq;

	dump_cq = container_of(dump_obj, struct ib_uverbs_dump_object_cq, obj);

	pr_debug("Found object CQ: %d\n", dump_cq->obj.handle);

	if (dump_obj->size != sizeof(*dump_cq)) {
		pr_err("Unmatched object size: %d expected %ld\n", dump_obj->size, sizeof(*dump_cq));
		return -1;
	}

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		goto out_err1;
	}
	ibverbs_object__init(*pb_obj);
	cq = xmalloc(sizeof(*cq));
	if (!cq) {
		goto out_err2;
	}
	ibverbs_cq__init(cq);

	cq->queue = pballoc_queue();
	if (!cq->queue) {
		goto out_err3;
	}

	cq->cqe = dump_cq->cqe;
	cq->comp_channel = dump_cq->comp_channel;
	cq->comp_vector = dump_cq->comp_vector;
        cq->comp_events_reported = dump_cq->comp_events_reported;
        cq->async_events_reported = dump_cq->async_events_reported;

        save_rxe_queue(cq->queue, &dump_cq->rxe);

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__CQ;
	(*pb_obj)->handle = dump_cq->obj.handle;
	(*pb_obj)->cq = cq;

	return sizeof(*dump_cq);

 out_err3:
	xfree(cq);
 out_err2:
	xfree(*pb_obj);
 out_err1:
	return -1;
}

static IbverbsAh *construct_pb_ibverbs_ah_attr(struct ib_uverbs_ah_attr *attr)
{
	IbverbsAh *ah_attr;

	ah_attr = xmalloc(sizeof(*ah_attr));
	if (!ah_attr) {
		goto out_err1;
	}
	ibverbs_ah__init(ah_attr);

	ah_attr->dgid.data = xmalloc(sizeof(attr->grh.dgid));
	if (!ah_attr->dgid.data) {
		goto out_err2;
	}

	ah_attr->dgid.len = sizeof(attr->grh.dgid);
	memcpy(ah_attr->dgid.data, attr->grh.dgid, ah_attr->dgid.len);
	ah_attr->flow_label = attr->grh.flow_label;
	ah_attr->sgid_index = attr->grh.sgid_index;
	ah_attr->hop_limit = attr->grh.hop_limit;
	ah_attr->traffic_class = attr->grh.traffic_class;

	ah_attr->dlid = attr->dlid;
	ah_attr->sl = attr->sl;
	ah_attr->src_path_bits = attr->src_path_bits;
	ah_attr->static_rate = attr->static_rate;
	ah_attr->is_global = attr->is_global;
	ah_attr->port_num = attr->port_num;

	ah_attr->pd_handle = UINT32_MAX;

	return ah_attr;

 out_err2:
	xfree(ah_attr);
 out_err1:
	return NULL;
}

static int extract_pb_ibverbs_ah_attr(IbverbsAh *ah_attr, struct ibv_ah_attr *attr)
{
	if (ah_attr->dgid.len != sizeof(attr->grh.dgid)) {
		pr_err("Unexpected dgid length: %lu expected %lu\n",
		       ah_attr->dgid.len, sizeof(attr->grh.dgid));
		goto out_err1;
	}

	memcpy(attr->grh.dgid.raw, ah_attr->dgid.data, ah_attr->dgid.len);
	attr->grh.flow_label = ah_attr->flow_label;
	attr->grh.sgid_index = ah_attr->sgid_index;
	attr->grh.hop_limit = ah_attr->hop_limit;
	attr->grh.traffic_class = ah_attr->traffic_class;

	attr->dlid = ah_attr->dlid;
	attr->sl = ah_attr->sl;
	attr->src_path_bits = ah_attr->src_path_bits;
	attr->static_rate = ah_attr->static_rate;
	attr->is_global = ah_attr->is_global;
	attr->port_num = ah_attr->port_num;

	return 0;

 out_err1:
	return -1;
}

static void destroy_pb_ibverbs_ah_attr(IbverbsAh *ah_attr)
{
	if (ah_attr) {
		xfree(ah_attr->dgid.data);
	}

	xfree(ah_attr);
}

static int dump_one_ibverbs_qp(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_qp *dump_qp;
	struct ib_uverbs_ah_attr attr;
	int dump_qp_size;
	IbverbsQp *qp;

	dump_qp = container_of(dump_obj, struct ib_uverbs_dump_object_qp, obj);
	dump_qp_size = sizeof(*dump_qp) + dump_qp->rxe.srq_wqe_size;

	pr_debug("Found object QP: %d\n", dump_qp->obj.handle);

	if (dump_obj->size != dump_qp_size) {
		pr_err("Unmatched object size: %d expected %ld\n", dump_obj->size, sizeof(*dump_qp));
		return -1;
	}

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		return -1;
	}
	ibverbs_object__init(*pb_obj);
	qp = xmalloc(sizeof(*qp));
	if (!qp) {
		goto out_err1;
	}
	ibverbs_qp__init(qp);

	qp->rq = pballoc_queue();
	if (!qp->rq) {
		goto out_err2;
	}

	qp->sq = pballoc_queue();
	if (!qp->sq) {
		goto out_err3;
	}

	qp->pd_handle = dump_qp->pd_handle;
	qp->qp_type = dump_qp->qp_type;
	qp->sq_sig_all = dump_qp->sq_sig_all;
	qp->qp_state = dump_qp->attr.qp_state;

	qp->pkey_index = dump_qp->attr.pkey_index;
	qp->port_num = dump_qp->attr.port_num;
	qp->qp_access_flags = dump_qp->attr.qp_access_flags;

	qp->path_mtu = dump_qp->attr.path_mtu;
	qp->dest_qp_num = dump_qp->attr.dest_qp_num;
	qp->rq_psn = dump_qp->attr.rq_psn;
	qp->max_dest_rd_atomic = dump_qp->attr.max_dest_rd_atomic;
	qp->min_rnr_timer = dump_qp->attr.path_mtu;

	memcpy(&attr, &dump_qp->attr.ah_attr, sizeof(attr));
	qp->ah_attr = construct_pb_ibverbs_ah_attr(&attr);
	if (!qp->ah_attr) {
		goto out_err4;
	}

	qp->sq_psn = dump_qp->attr.sq_psn;
	qp->max_rd_atomic = dump_qp->attr.max_rd_atomic;
	qp->retry_cnt = dump_qp->attr.retry_cnt;
	qp->rnr_retry = dump_qp->attr.rnr_retry;
	qp->timeout = dump_qp->attr.timeout;
	qp->qp_num = dump_qp->qp_num;
	qp->wqe_index = dump_qp->rxe.wqe_index;
	qp->req_opcode = dump_qp->rxe.req_opcode;
	qp->comp_psn = dump_qp->rxe.comp_psn;
	qp->comp_opcode = dump_qp->rxe.comp_opcode;
	qp->msn = dump_qp->rxe.msn;
	qp->resp_opcode = dump_qp->rxe.resp_opcode;

	qp->rcq_handle = dump_qp->rcq_handle;

	qp->scq_handle = dump_qp->scq_handle;

	qp->srq_handle = dump_qp->srq_handle;
	if (qp->srq_handle != UINT32_MAX) {
		/* There is an SRQ WQE */
		qp->has_srq_wqe = true;
		qp->srq_wqe.data = xmalloc(dump_qp->rxe.srq_wqe_size);
		if (!qp->srq_wqe.data) {
			goto out_err5;
		}
		qp->srq_wqe.len = dump_qp->rxe.srq_wqe_size;
		memcpy(qp->srq_wqe.data, &dump_qp->rxe.data[dump_qp->rxe.srq_wqe_offset], qp->srq_wqe.len);
	}

	qp->max_send_wr = dump_qp->attr.cap.max_send_wr;
	qp->max_recv_wr = dump_qp->attr.cap.max_recv_wr;
	qp->max_send_sge = dump_qp->attr.cap.max_send_sge;
	qp->max_recv_sge = dump_qp->attr.cap.max_recv_sge;
	qp->max_inline_data = dump_qp->attr.cap.max_inline_data;

	save_rxe_queue(qp->sq, &dump_qp->rxe.sq);
	save_rxe_queue(qp->rq, &dump_qp->rxe.rq);

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__QP;
	(*pb_obj)->handle = dump_qp->obj.handle;
	(*pb_obj)->qp = qp;

	pr_debug("Dumped QP type %d\n", qp->qp_type);

	return dump_qp_size;

 out_err5:
	destroy_pb_ibverbs_ah_attr(qp->ah_attr);
 out_err4:
	xfree(qp->sq);
 out_err3:
	xfree(qp->rq);
 out_err2:
	xfree(qp);
 out_err1:
	xfree(*pb_obj);

	return -1;
}

static int dump_one_ibverbs_srq(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_srq *dump_srq;
	IbverbsSrq *srq;

	dump_srq = container_of(dump_obj, struct ib_uverbs_dump_object_srq, obj);

	pr_debug("Found object SRQ: %d\n", dump_srq->obj.handle);

	if (dump_obj->size != sizeof(*dump_srq)) {
		pr_err("Unmatched object size: %d expected %ld\n", dump_obj->size, sizeof(*dump_srq));
		return -1;
	}

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		return -1;
	}
	ibverbs_object__init(*pb_obj);
	srq = xmalloc(sizeof(*srq));
	if (!srq) {
		goto out_err1;
	}
	ibverbs_srq__init(srq);

	srq->queue = pballoc_queue();
	if (!srq->queue) {
		goto out_err2;
	}

	srq->pd_handle = dump_srq->pd_handle;
	srq->cq_handle = dump_srq->cq_handle;
	srq->srq_type = dump_srq->srq_type;
	srq->max_wr = dump_srq->max_wr;
	srq->max_sge = dump_srq->max_sge;
	srq->srq_limit = dump_srq->srq_limit;

	save_rxe_queue(srq->queue, &dump_srq->queue);

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__SRQ;
	(*pb_obj)->handle = dump_srq->obj.handle;
	(*pb_obj)->srq = srq;

	pr_debug("Dumped SRQ type %d\n", srq->srq_type);

	return sizeof(*dump_srq);

 out_err2:
	xfree(srq);
 out_err1:
	xfree(*pb_obj);

	return -1;
}

static int dump_one_ibverbs_ah(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_ah *dump_ah;
	struct ib_uverbs_ah_attr attr;
	IbverbsAh *ah;

	dump_ah = container_of(dump_obj, struct ib_uverbs_dump_object_ah, obj);
	pr_debug("Found object AH: %d dlid: %d port %d\n", dump_ah->obj.handle, dump_ah->attr.dlid, dump_ah->attr.port_num);

	if (dump_obj->size != sizeof(*dump_ah)) {
		pr_err("Unmatched object size: %d expected %ld\n", dump_obj->size, sizeof(*dump_ah));
		return -1;
	}

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		return -1;
	}
	ibverbs_object__init(*pb_obj);

	memcpy(&attr, &dump_ah->attr, sizeof(attr));
	ah = construct_pb_ibverbs_ah_attr(&attr);
	if (!ah) {
		goto out_err1;
	}
	ah->pd_handle = dump_ah->pd_handle;

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__AH;
	(*pb_obj)->handle = dump_ah->obj.handle;
	(*pb_obj)->ah = ah;

	return sizeof(*dump_ah);

 out_err1:
	xfree(pb_obj);
	return -1;
}

static int dump_one_ibverbs(int lfd, u32 id, const struct fd_parms *p)
{
	struct cr_img *img;
	FileEntry fe = FILE_ENTRY__INIT;
	IbverbsEntry ibv = IBVERBS_ENTRY__INIT;

	if (dump_one_reg_file(lfd, id, p))
		return -1;

	pr_info("Dumping ibverbs-file %d with id %#x\n", lfd, id);

	ibv.id = id;
	ibv.flags = p->flags;
	ibv.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__IBVERBS;
	fe.id = ibv.id;
	fe.ibv = &ibv;

	struct ibv_device *ibdev;
	struct ibv_context *ctx;
	const char *ib_devname = "rocep2s4";
	ibdev = find_ibdev(ib_devname);
	if (!ibdev) {
		pr_err("IB device %s not found\n", ib_devname);
		return -1;
	}

	ctx = ibv_reopen_device(ibdev, lfd);
	if (!ctx) {
		pr_perror("Failed to open the device %d\n", lfd);
		return -1;
	}

	/* XXX: hack to avoid error upon exit */
	ctx->async_fd = lfd;

	int ret = -1;
	int count;
	const unsigned int dump_size = 64*1024;
	void *dump = xzalloc(dump_size);
	if (!dump) {
		pr_err("Failed to allocate dump buffer of size %d\n", dump_size);
		goto out;
	}

	ret = ibv_dump_context(ctx, &count, dump, dump_size);
	if (ret) {
		pr_err("Failed to dump protection domain: %d\n", ret);
		goto out;
	}

	pr_debug("Found total Objs: %d\n", count);

	ibv.n_objs = count;
	ibv.objs = xzalloc(pb_repeated_size(&ibv, objs));

	if (!ibv.objs) {
		pr_err("Failed to allocate memory for protection domains\n");
		goto out;
	}

	void *cur_obj = dump;
	for (int i = 0; i < count; i++) {
		struct ib_uverbs_dump_object *obj = cur_obj;
		pr_debug("Found obj of type: %d %p %p %d\n", obj->type, cur_obj, obj, *(uint32_t *)cur_obj);
		switch(obj->type) {
		case IB_UVERBS_OBJECT_PD:
			ret = dump_one_ibverbs_pd(&ibv.objs[i], obj);
			break;
		case IB_UVERBS_OBJECT_MR:
			ret = dump_one_ibverbs_mr(&ibv.objs[i], obj, p->vmas);
			break;
		case IB_UVERBS_OBJECT_CQ:
			ret = dump_one_ibverbs_cq(&ibv.objs[i], obj);
			break;
		case IB_UVERBS_OBJECT_QP:
			ret = dump_one_ibverbs_qp(&ibv.objs[i], obj);
			break;
		case IB_UVERBS_OBJECT_AH:
			ret = dump_one_ibverbs_ah(&ibv.objs[i], obj);
			break;
		case IB_UVERBS_OBJECT_SRQ:
			ret = dump_one_ibverbs_srq(&ibv.objs[i], obj);
			break;
		case IB_UVERBS_OBJECT_COMP_CHANNEL:
			ret = dump_one_ibverbs_comp_channel(&ibv.objs[i], obj);
			break;
		default:
			pr_err("Unknown object type: %d\n", obj->type);
			ret = -1;
			break;
		}
		if (ret < 0) {
			goto out;
		}
		pr_debug("Moving pointer by %d\n", ret);
		cur_obj += ret;
	}

	img = img_from_set(glob_imgset, CR_FD_FILES);
	ret = pb_write_one(img, &fe, PB_FILE);
	if (ret) {
		pr_perror("Failed to write image\n");
	}

 out:
	/* XXX: Objects are deeply hierarchical. Memory leaks are unavoidable */
	xfree(dump);
	if (ibv.objs) {
		for (int i = 0; i < count; i++) {
			xfree(ibv.objs[i]);
		}
		xfree(ibv.objs);
	}
	return ret;
}

const struct fdtype_ops ibverbs_dump_ops = {
	.type	= FD_TYPES__IBVERBS,
	.dump	= dump_one_ibverbs,
};

#define ELEM_COUNT 140
static int last_event_fd;
static void *objects[IB_UVERBS_OBJECT_TOTAL][ELEM_COUNT];

static int ibverbs_remember_object(int object_type, int id, void *object)
{
	if (id >= ELEM_COUNT) {
		return -ENOMEM;
	}

	if (objects[object_type][id] != NULL) {
		return -EINVAL;
	}

	objects[object_type][id] = object;

	return 0;
}

static void *ibverbs_get_object(int object_type, int id)
{
	if (id >= ELEM_COUNT) {
		return NULL;
	}

	return objects[object_type][id];
}

static int rxe_set_parameter(int fd, uint32_t new_val, uint32_t *old_val)
{
	char buf[32];

	if (old_val != NULL) {
		int ret = pread(fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			pr_err("Failed to read old QPN value: %s", strerror(errno));
			return -1;
		}

		ret = sscanf(buf, "%u", old_val);
		if (ret != 1) {
			pr_err("Failed to parse input: %s", strerror(errno));
			return -1;
		}
	}

	if (snprintf(buf, sizeof(buf), "%d\n", new_val) < 0) {
		pr_err("Failed to format buffer: %s", strerror(errno));
		return -1;
	}

        if (pwrite(fd, buf, strlen(buf), 0) < 0) {
		pr_err("Failed to write %s: %s", buf, strerror(errno));
		return -1;
        }

	return 0;
}

static int rxe_set_last_qpn(uint32_t qpn, uint32_t *old_qpn)
{
	/* XXX: Should actually do this in kernel in rxe_pool.c: alloc_index */
	uint32_t last_qpn = qpn - 16;
	int fd = get_service_fd(CR_IBVERBS_RXE_QPN);

	if (rxe_set_parameter(fd, last_qpn, old_qpn) < 0) {
		pr_err("Failed to set last QPN");
		return -1;
        }

        if (old_qpn != NULL) {
		*old_qpn += 16;
	}

	return 0;
}

static int rxe_set_last_mrn(uint32_t new_mrn, uint32_t *old_mrn)
{
	int fd = get_service_fd(CR_IBVERBS_RXE_MRN);
	if (rxe_set_parameter(fd, new_mrn, old_mrn) < 0) {
		pr_err("Failed to set last MRN");
		return -1;
	}

        return 0;
}

static int ibverbs_restore_pd(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	struct ibv_context *ibcontext = entry->ibcontext;
	IbverbsObject *obj = entry->obj;
	struct ibv_pd *pd;
	pd = ibv_alloc_pd(ibcontext);
	if (!pd) {
		pr_err("Failed to create a PD: %s\n", strerror(errno));
		return -1;
	}

	if (pd->handle != obj->handle) {
		pr_err("Unexpected protection domain handle: %d vs %d\n", obj->handle, pd->handle);
		goto err;
	}

	if (ibverbs_remember_object(IB_UVERBS_OBJECT_PD, pd->handle, pd)) {
		pr_err("Failed to remember object\n");
		goto err;
	}

	pr_debug("Restored PD object %d\n", obj->handle);
	return 0;

 err:
	ibv_dealloc_pd(pd);
	return -1;
}

static int ibverbs_restore_comp_channel(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	IbverbsObject *obj = entry->obj;

	pr_debug("Restoring comp_channel object %d\n", obj->handle);

#if 0
	struct ibv_comp_channel *comp_channel;
	struct ibv_context *ibcontext = entry->ibcontext;
	comp_channel = ibv_create_comp_channel(ibcontext);
	if (!comp_channel) {
		return -1;
	}
	pr_debug("Restoring comp_channel object %d fd %d\n", obj->handle, comp_channel->fd);

	/* if (comp_channel->fd != obj->handle) { */
	/* 	pr_err("Unexpected protection domain handle: %d vs %d\n", obj->handle, pd->handle); */
	/* 	goto err; */
	/* } */

	if (ibverbs_remember_object(IB_UVERBS_OBJECT_COMP_CHANNEL, comp_channel->fd, comp_channel)) {
		pr_err("Failed to remember object\n");
		goto err;
	}

	pr_debug("Restored comp_channel object %d fd %d\n", obj->handle, comp_channel->fd);
	return 0;

 err:
	ibv_destroy_comp_channel(comp_channel);
	return -1;
#else
	return 0;
#endif
}

static int ibverbs_restore_mr(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	IbverbsObject *obj = entry->obj;
	IbverbsMr *pb_mr = obj->mr;

	struct ibv_mr *ibv_mr;
	struct ibv_pd *pd;
	u32 old_mrn;
	int ret;

	pd = ibverbs_get_object(IB_UVERBS_OBJECT_PD, pb_mr->pd_handle);
	if (!pd) {
		pr_err("PD object with id %d is not known\n", pb_mr->pd_handle);
		return -1;
	}

	ret = rxe_set_last_mrn(pb_mr->mrn - 1, &old_mrn);
	if (ret < 0) {
		pr_err("Failed to set MRN\n");
		return -1;
	}

	ibv_mr = ibv_reg_mr(pd, (void *)pb_mr->address, pb_mr->length,
			    pb_mr->access);
	if (!ibv_mr) {
		pr_err("ibv_reg_mr failed: %s\n", strerror(errno));
		return -1;
	}
	pr_debug("Restoring MR area: @%p - %p\n", (void *)pb_mr->address, (void *)pb_mr->length);

	ret = rxe_set_last_mrn(old_mrn, NULL);
	if (ret < 0) {
		pr_err("Failed to reset MRN\n");
		return -1;
	}

	struct rxe_dump_mr args;

	args.lkey = pb_mr->lkey;
	args.rkey = pb_mr->rkey;

	pr_debug("CRIU restore keys: %d==%d %d==%d\n", args.lkey, pb_mr->lkey, args.rkey, pb_mr->rkey);

	ret = ibv_restore_object(entry->ibcontext, (void **)&ibv_mr,
				 IB_UVERBS_OBJECT_MR, IBV_RESTORE_MR_KEYS,
				 &args, sizeof(args));
	if (ret) {
		pr_err("Failed to restore MR: %s\n", strerror(errno));
		return -1;
	}

	if (ibverbs_remember_object(IB_UVERBS_OBJECT_MR, ibv_mr->handle, ibv_mr)) {
		pr_err("Failed to remember object\n");
		return -1;
	}

	pr_debug("Restored MR object %d\n", obj->handle);
	return 0;
}

static int ibverbs_restore_cq(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	IbverbsObject *obj = entry->obj;
	IbverbsCq *cq = obj->cq;
	struct ibv_cq *ibv_cq;

	if (!cq) {
		return -1;
	}

	struct ibv_restore_cq args;

	if (!cq->queue) {
		return -1;
	}

	if (!cq->queue->rxe) {
		return -1;
	}

	args.cqe = cq->cqe;
	args.queue.vm_start = cq->queue->start;
	args.queue.vm_size = cq->queue->size;
	args.comp_vector = cq->comp_vector;
	args.channel = NULL;

	void * tmp_buf = malloc(args.queue.vm_size);
	if (!tmp_buf) {
		pr_err("Failed to allocate temporary buffer\n");
		return -1;
	}
	memmove(tmp_buf, (void *)args.queue.vm_start, args.queue.vm_size);
	munmap((void *)args.queue.vm_start, args.queue.vm_size);

	int ret = ibv_restore_object(entry->ibcontext, (void **)&ibv_cq,
				     IB_UVERBS_OBJECT_CQ, IBV_RESTORE_CQ_CREATE,
				     &args, sizeof(args));
	if (ret) {
		pr_err("Failed to create CQ\n");
		return -1;
	}

	memmove((void *)args.queue.vm_start, tmp_buf, args.queue.vm_size);
	free(tmp_buf);

	if (args.queue.vm_size > 0) {
		if (keep_address_range((u64)args.queue.vm_start, args.queue.vm_size))
			return -1;
	}

	if (ibverbs_remember_object(IB_UVERBS_OBJECT_CQ, ibv_cq->handle, ibv_cq)) {
		pr_err("Failed to remember CQ object with id %d\n", ibv_cq->handle);
		return -1;
	}

	struct ib_uverbs_restore_object_cq_refill dump_queue;
	restore_rxe_queue(&dump_queue.rxe, cq->queue);
	dump_queue.comp_events_reported = cq->comp_events_reported;
        dump_queue.async_events_reported = cq->async_events_reported;

	ret = ibv_restore_object(entry->ibcontext,
				 (void **)&ibv_cq, IB_UVERBS_OBJECT_CQ,
				 IBV_RESTORE_CQ_REFILL, &dump_queue, sizeof(dump_queue));
	if (ret) {
		pr_err("Failed to restore CQ\n");
		return -1;
	}

	pr_debug("Restored CQ object %d\n", obj->handle);
	return 0;
}

static int ibverbs_restore_qp(struct ibverbs_list_entry * entry, struct task_restore_args *ta)
{
	int ret;
	uint32_t old_qpn;
	IbverbsObject *obj = entry->obj;
	IbverbsQp *qp = obj->qp;
	struct ibv_qp *ibv_qp;

	struct ibv_restore_qp args;

	args.pd = ibverbs_get_object(IB_UVERBS_OBJECT_PD, qp->pd_handle);
	if (!args.pd) {
		pr_err("Failed to find PD object with id: %d\n", qp->pd_handle);
		return -1;
	}

	if (!qp) {
		return -1;
	}

	if (!qp->sq) {
		return -1;
	}

	if (!qp->sq->rxe) {
		return -1;
	}

	if (!qp->rq) {
		return -1;
	}

	if (!qp->rq->rxe) {
		return -1;
	}

	args.attr.send_cq = ibverbs_get_object(IB_UVERBS_OBJECT_CQ, qp->scq_handle);
	if (!args.attr.send_cq) {
		pr_err("Failed to find CQ object with id: %d\n", qp->scq_handle);
		return -1;
	}

	args.attr.recv_cq = ibverbs_get_object(IB_UVERBS_OBJECT_CQ, qp->rcq_handle);
	if (!args.attr.recv_cq) {
		pr_err("Failed to find CQ object with id: %d\n", qp->rcq_handle);
		return -1;
	}

	if (qp->srq_handle != UINT32_MAX) {
		args.attr.srq = ibverbs_get_object(IB_UVERBS_OBJECT_SRQ, qp->srq_handle);
		if (!args.attr.srq) {
			pr_err("Failed to find SRQ object with id: %d\n", qp->srq_handle);
			return -1;
		}
	} else {
		args.attr.srq = NULL;
	}

	args.attr.qp_context = NULL;
	args.attr.qp_type = qp->qp_type;
	args.attr.sq_sig_all = qp->sq_sig_all;

	args.attr.cap.max_send_wr = qp->max_send_wr;
	args.attr.cap.max_recv_wr = qp->max_recv_wr;
	args.attr.cap.max_send_sge = qp->max_send_sge;
	args.attr.cap.max_recv_sge = qp->max_recv_sge;
	args.attr.cap.max_inline_data = qp->max_inline_data;

	args.rq.vm_start = qp->rq->start;
	args.rq.vm_size = qp->rq->size;

	args.sq.vm_start = qp->sq->start;
	args.sq.vm_size = qp->sq->size;

	void * rq_tmp = malloc(args.rq.vm_size);
	if (!rq_tmp) {
		pr_err("Failed to allocate temporary buffer\n");
		return -1;
	}
	memmove(rq_tmp, (void *)args.rq.vm_start, args.rq.vm_size);
	munmap((void *)args.rq.vm_start, args.rq.vm_size);
	void * sq_tmp = malloc(args.sq.vm_size);
	if (!sq_tmp) {
		pr_err("Failed to allocate temporary buffer\n");
		return -1;
	}
	memmove(sq_tmp, (void *)args.sq.vm_start, args.sq.vm_size);
	munmap((void *)args.sq.vm_start, args.sq.vm_size);

	ret = rxe_set_last_qpn(qp->qp_num, &old_qpn);
	if (ret < 0) {
		return -1;
	}

	ret = ibv_restore_object(entry->ibcontext,
				 (void **)&ibv_qp, IB_UVERBS_OBJECT_QP,
				 IBV_RESTORE_QP_CREATE, &args, sizeof(args));
	if (ret) {
		pr_err("Failed to restore QP\n");
		return -1;
	}

	if (ibv_qp->qp_num != qp->qp_num) {
		pr_err("Nonmatching QP number: %u expected %u\n", ibv_qp->qp_num, qp->qp_num);
		return -1;
	}

	ret = rxe_set_last_qpn(old_qpn, NULL);
	if (ret < 0) {
		return -1;
	}

	memmove((void *)args.rq.vm_start, rq_tmp, args.rq.vm_size);
	free(rq_tmp);
	memmove((void *)args.sq.vm_start, sq_tmp, args.sq.vm_size);
	free(sq_tmp);

	if (args.rq.vm_size > 0) {
		if (keep_address_range((u64) args.rq.vm_start, args.rq.vm_size)) {
			pr_err("Adding range %lx+ %lx failed\n",
			       (u64) args.rq.vm_start, args.rq.vm_size);
			return -1;
		}
	}

	if (args.sq.vm_size > 0) {
		if (keep_address_range((u64) args.sq.vm_start, args.sq.vm_size)) {
			pr_err("Adding range %lx+ %lx failed\n",
			       (u64) args.sq.vm_start, args.sq.vm_size);
			return -1;
		}
	}

	while (1) {
		int flags;
		struct ibv_qp_attr attr;

		/* Check target state */
		if (qp->qp_state == IB_QPS_RESET) {
		  /* Do nothing */
		  break;
		}

		/* Move to init state */
		flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT;
		memset(&attr, 0, sizeof(attr));

		attr.qp_state = IB_QPS_INIT;
		attr.pkey_index = qp->pkey_index;
		attr.port_num = qp->port_num;


		if (qp->qp_type == IB_QPT_RC) {
			flags |= IBV_QP_ACCESS_FLAGS;
			attr.qp_access_flags = qp->qp_access_flags;
		} else if (qp->qp_type == IB_QPT_UD) {
			pr_debug("Restoring UD QP\n");
			break;
		} else {
			pr_err("Unsupported\n");
			return -1;
		}

		ret = ibv_modify_qp(ibv_qp, &attr, flags);
		if (ret) {
			pr_err("Modify to init failed: %s\n", strerror(errno));
			return -1;
		}

		/* Check target state */
		if (qp->qp_state == IB_QPS_INIT) {
		  break;
		}

		/* Move to RTR state */
		flags = IBV_QP_STATE;
		memset(&attr, 0, sizeof(attr));

		attr.qp_state = IB_QPS_RTR;
		if (qp->qp_type == IB_QPT_RC) {
			flags |= (IBV_QP_AV |
				  IBV_QP_PATH_MTU |
				  IBV_QP_DEST_QPN |
				  IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER);

			extract_pb_ibverbs_ah_attr(qp->ah_attr, &attr.ah_attr);

			attr.path_mtu = qp->path_mtu;
			attr.dest_qp_num = qp->dest_qp_num;
			attr.rq_psn = qp->rq_psn;
			attr.max_dest_rd_atomic = qp->max_dest_rd_atomic;
			attr.min_rnr_timer = qp->min_rnr_timer;
		} else {
			pr_err("Unsupported\n");
			return -1;
		}

		ret = ibv_modify_qp(ibv_qp, &attr, flags);
		if (ret) {
			pr_err("Modify to init failed: %s\n", strerror(errno));
			return -1;
		}

		/* Check target state */
		if (qp->qp_state == IB_QPS_RTR) {
			break;
		}

		/* Move to RTS state */
		flags = IBV_QP_STATE;
		memset(&attr, 0, sizeof(attr));

		attr.qp_state = IB_QPS_RTS;
		if (qp->qp_type == IB_QPT_RC) {
			flags |= (IBV_QP_SQ_PSN |
				  IBV_QP_MAX_QP_RD_ATOMIC |
				  IBV_QP_RETRY_CNT |
				  IBV_QP_RNR_RETRY |
				  IBV_QP_TIMEOUT);
			attr.sq_psn = qp->sq_psn;
			attr.max_rd_atomic = qp->max_rd_atomic;
			attr.retry_cnt = qp->retry_cnt;
			attr.rnr_retry = qp->rnr_retry;
			attr.timeout = qp->timeout;
		} else {
			pr_err("Unsupported\n");
			return -1;
		}

		ret = ibv_modify_qp(ibv_qp, &attr, flags);
		if (ret) {
			pr_err("Modify to init failed: %s\n", strerror(errno));
			return -1;
		}

		if (qp->qp_state == IB_QPS_RTS) {
			break;
		}

		pr_err("Unknown state %d reached\n", qp->qp_state);
		return -1;
	}

	if (qp->qp_type == IB_QPT_RC) {
		struct rxe_dump_qp *dump_qp;
		int size = sizeof(*dump_qp);

		if (qp->has_srq_wqe) {
			size += qp->srq_wqe.len;
		}

		dump_qp = xmalloc(size);
		if (!dump_qp) {
			return -1;
		}

		restore_rxe_queue(&dump_qp->rq, qp->rq);
		restore_rxe_queue(&dump_qp->sq, qp->sq);
		dump_qp->wqe_index = qp->wqe_index;
		dump_qp->req_opcode = qp->req_opcode;
		dump_qp->comp_psn = qp->comp_psn;
		dump_qp->comp_opcode = qp->comp_opcode;
		dump_qp->msn = qp->msn;
		dump_qp->resp_opcode = qp->resp_opcode;

		if (qp->has_srq_wqe) {
			/* XXX: should handle non-zero offset */
			dump_qp->srq_wqe_offset = 0;
			dump_qp->srq_wqe_size = qp->srq_wqe.len;
			memcpy(&dump_qp->data[dump_qp->srq_wqe_offset], &qp->srq_wqe.data, qp->srq_wqe.len);
		}

		ret = ibv_restore_object(entry->ibcontext,
					 (void **)&ibv_qp, IB_UVERBS_OBJECT_QP,
					 IBV_RESTORE_QP_REFILL, dump_qp, size);
		if (ret) {
			pr_err("Failed to restore QP\n");
			return -1;
		}

		xfree(dump_qp);
	}

	pr_debug("Restored QP object %d\n", obj->handle);
	return 0;
}

static int ibverbs_restore_srq(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	int ret;
	IbverbsObject *obj = entry->obj;
	IbverbsSrq *srq = obj->srq;
	struct ibv_srq *ibv_srq;

	struct ibv_restore_srq args;

	args.pd = ibverbs_get_object(IB_UVERBS_OBJECT_PD, srq->pd_handle);
	if (!args.pd) {
		pr_err("Failed to find PD object with id: %d\n", srq->pd_handle);
		return -1;
	}

	if (!srq) {
		return -1;
	}

	if (!srq->queue) {
		return -1;
	}

	if (!srq->queue->rxe) {
		return -1;
	}

	if (srq->cq_handle != UINT32_MAX) {
		pr_err("CQs are not supported for SRQs: %x\n", srq->cq_handle);
		return -ENOTSUP;
	}

	args.attr.srq_context = NULL;
	args.attr.attr.max_wr = srq->max_wr;
	args.attr.attr.max_sge = srq->max_sge;
	args.attr.attr.srq_limit = srq->srq_limit;

	args.queue.vm_start = srq->queue->start;
	args.queue.vm_size = srq->queue->size;

	void * queue_tmp = malloc(args.queue.vm_size);
	if (!queue_tmp) {
		pr_err("Failed to allocate temporary buffer\n");
		return -1;
	}
	memmove(queue_tmp, (void *)args.queue.vm_start, args.queue.vm_size);
	munmap((void *)args.queue.vm_start, args.queue.vm_size);

	ret = ibv_restore_object(entry->ibcontext,
				 (void **)&ibv_srq, IB_UVERBS_OBJECT_SRQ,
				 IBV_RESTORE_SRQ_CREATE, &args, sizeof(args));
	if (ret) {
		pr_err("Failed to restore QP\n");
		return -1;
	}

	memmove((void *)args.queue.vm_start, queue_tmp, args.queue.vm_size);
	free(queue_tmp);

	pr_debug("SRQ adding range %p + 0x%lx \n", (void *) args.queue.vm_start, args.queue.vm_size);
	if (args.queue.vm_size > 0) {
		if (keep_address_range((u64) args.queue.vm_start, args.queue.vm_size)) {
			pr_err("Adding range %lx+ %lx failed\n",
			       (u64) args.queue.vm_start, args.queue.vm_size);
			return -1;
		}
	}

	struct rxe_dump_queue dump_queue;
	restore_rxe_queue(&dump_queue, srq->queue);

	ret = ibv_restore_object(entry->ibcontext,
				 (void **)&ibv_srq, IB_UVERBS_OBJECT_SRQ,
				 IBV_RESTORE_SRQ_REFILL, &dump_queue, sizeof(dump_queue));
	if (ret) {
		pr_err("Failed to restore SRQ: %s\n", strerror(errno));
		return -1;
	}

	if (ibverbs_remember_object(IB_UVERBS_OBJECT_SRQ, ibv_srq->handle, ibv_srq)) {
		pr_err("Failed to remember SRQ object with id %d\n", ibv_srq->handle);
		return -1;
	}

	pr_debug("Restored SRQ object %d\n", obj->handle);
	return 0;
}

static int ibverbs_restore_ah(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	IbverbsObject *obj = entry->obj;
	IbverbsAh *ah = obj->ah;
	struct ibv_ah *ibv_ah;
	struct ibv_pd *pd;

	struct ibv_ah_attr attr;

	pd = ibverbs_get_object(IB_UVERBS_OBJECT_PD, ah->pd_handle);
	if (!pd) {
		pr_err("Failed to find PD object with id: %d\n", ah->pd_handle);
		return -1;
	}

	if (extract_pb_ibverbs_ah_attr(ah, &attr)) {
		return -1;
	}

	ibv_ah = ibv_create_ah(pd, &attr);
	if (!ibv_ah) {
		pr_err("Failed to create AH\n");
		return -1;
	}

	if (ibverbs_remember_object(IB_UVERBS_OBJECT_AH, ibv_ah->handle, ibv_ah)) {
		pr_err("Failed to remember AH object with id %d\n", ibv_ah->handle);
		return -1;
	}

	pr_debug("Restored AH object %d\n", obj->handle);
	return 0;
}

static int ibverbs_open(struct file_desc *d, int *new_fd)
{
	struct ibverbs_file_info *info;
	struct ibv_device *ibdev;
	struct ibv_context *ibcontext;
	const char *ib_devname = "rocep2s4";

	info = container_of(d, struct ibverbs_file_info, d);

	pr_info("Opening device %s\n", ib_devname);

	ibdev = find_ibdev(ib_devname);
	if (!ibdev) {
		pr_perror("IB device %s not found\n", ib_devname);
		goto err;
	}

	ibcontext = ibv_open_device(ibdev);
	if (!ibcontext) {
		pr_perror("Failed to open the device\n");
		goto err;
	}
	IBCONTEXT = ibcontext;
	pr_debug("Opened device: cmd_fd %d async_fd %d file_desc->id %d\n",
		 ibcontext->cmd_fd, ibcontext->async_fd, d->id);

	if (rst_file_params(ibcontext->cmd_fd, info->ibv->fown, info->ibv->flags)) {
		pr_perror("Can't restore params on ibverbs %#08x\n",
			  info->ibv->id);
		goto err_close;
	}

	pr_debug("Available objects for the context: %ld\n", info->ibv->n_objs);

	/* The reverse order of objects in the list is important, because the
	 * dump we get first has MR, then PD */
	for (int i = 0; i < info->ibv->n_objs ; i++) {
		struct ibverbs_list_entry *le = xzalloc(sizeof(*le));

		le->ibdev = ibdev;
		le->ibcontext = ibcontext;
		le->obj = info->ibv->objs[i];

		pr_debug("Installing type %d\n", le->obj->type);
		switch (le->obj->type) {
		case IBVERBS_OBJECT_TYPE__PD:
			le->restore = ibverbs_restore_pd;
			break;
		case IBVERBS_OBJECT_TYPE__MR:
			le->restore = ibverbs_restore_mr;
			break;
		case IBVERBS_OBJECT_TYPE__CQ:
			le->restore = ibverbs_restore_cq;
			break;
		case IBVERBS_OBJECT_TYPE__QP:
			le->restore = ibverbs_restore_qp;
			break;
		case IBVERBS_OBJECT_TYPE__AH:
			le->restore = ibverbs_restore_ah;
			break;
		case IBVERBS_OBJECT_TYPE__SRQ:
			le->restore = ibverbs_restore_srq;
			break;
		case IBVERBS_OBJECT_TYPE__COMP_CHANNEL:
			le->restore = ibverbs_restore_comp_channel;
			break;
		default:
			pr_err("Object type is not supported: %d\n", le->obj->type);
			goto err_close;
		}
		list_add(&le->restore_list, &ibverbs_restore_objects);
	}

	pr_info("Opened a device %d %d\n", ibcontext->cmd_fd, ibcontext->async_fd);
	last_event_fd = ibcontext->async_fd;

	*new_fd = ibcontext->cmd_fd;

	ibcontext->cmd_fd = 8;
	ibcontext->cmd_fd = 16;
	ibcontext->async_fd = 17;

	if (append_context(ibcontext->cmd_fd)) {
	/* if (append_context(18)) { */
		goto err_close;
	}

	return 0;

 err_close:
	ibv_close_device(ibcontext);
 err:
	return -1;
}

static struct file_desc_ops ibverbs_desc_ops = {
	.type = FD_TYPES__IBVERBS,
	.open = ibverbs_open,
};

static int collect_one_ibverbs(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct ibverbs_file_info *info = obj;

	info->ibv = pb_msg(msg, IbverbsEntry);
	pr_info_ibverbs("Collected", info->ibv);
	pr_info("Collected %p\n", info);
	pr_info("Collected %p\n", &info->d);
	int ret = file_desc_add(&info->d, info->ibv->id, &ibverbs_desc_ops);
	pr_info("Collected %d\n", ret);
	return ret;
}

struct collect_image_info ibv_cinfo = {
	.fd_type = CR_FD_IBVERBS,
	.pb_type = PB_IBVERBS,
	.priv_size = sizeof(struct ibverbs_file_info),
	.collect = collect_one_ibverbs,
};

static int ibverbs_area_open(int pid, struct vma_area *vma)
{
	if (!vma_area_is(vma, VMA_AREA_IBVERBS)) {
		pr_err("Unknown area found\n");
		return -1;
	}

	void *addr;

	addr = mmap((void *)vma->e->start, vma_entry_len(vma->e),
		    vma->e->prot | PROT_WRITE,
		    vma->e->flags | MAP_FIXED,
		    vma->e->fd, vma->e->pgoff);
	if (addr == MAP_FAILED) {
		pr_perror("Unable to map VMA_IBVERBS");
		return -1;
	}

	if (keep_address_range(vma->e->start, vma_entry_len(vma->e))) {
		return -1;
	}

	return 0;
}

int collect_ibverbs_area(struct vma_area *vma)
{
	vma->vm_open = ibverbs_area_open;
	return 0;
}

int prepare_ibverbs(struct pstree_item *me, struct task_restore_args *ta)
{
	struct ibverbs_list_entry *le;

	int i = 0;
	list_for_each_entry(le, &ibverbs_restore_objects, restore_list) {
		pr_debug("Restoring object %d of type %d fd %d\n", i++, le->obj->type, le->ibcontext->cmd_fd);
		int ret = le->restore(le, ta);
		if (ret < 0) {
			pr_err("Failed to restore object of type: %d\n", le->obj->type);
			return -1;
		}
	}

	return prepare_contexts(ta);
}

/* Ibevent related functions */

int is_ibevent_link(char *link)
{
	return is_anon_link_type(link, "[infinibandevent]");
}

struct ibevent_file_info {
	IbeventEntry		*ibe;
	struct file_desc	d;
};

static void pr_info_ibevent(char *action, IbeventEntry *ibe)
{
	pr_info("IB event %s: id %#08x flags %#04x\n", action, ibe->id, ibe->flags);
	/* pr_info("IB event %s: id %#08x\n", action, ibe->id); */
}

static int dump_one_ibevent(int lfd, u32 id, const struct fd_parms *p)
{
	struct cr_img *img;
	FileEntry fe = FILE_ENTRY__INIT;
	IbeventEntry ibe = IBEVENT_ENTRY__INIT;

	if (parse_fdinfo(lfd, FD_TYPES__IBEVENTFD, &ibe))
		return -1;

	pr_info("Dumping ibevent-file %d with id %#x\n", lfd, id);

	ibe.id = id;
	ibe.flags = p->flags;
	ibe.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__IBEVENTFD;
	fe.id = ibe.id;
	fe.ibe = &ibe;

	img = img_from_set(glob_imgset, CR_FD_FILES);
	return pb_write_one(img, &fe, PB_FILE);
}

const struct fdtype_ops ibevent_dump_ops = {
	.type = FD_TYPES__IBEVENTFD,
	.dump = dump_one_ibevent,
};

static int ibevent(void)
{
	pr_info("ibevent %d\n", __LINE__);
	if (last_event_fd)
		return last_event_fd;
	return -1;
}

static int ibevent_open(struct file_desc *d, int *new_fd)
{
	struct ibevent_file_info *info;
	int tmp;

	info = container_of(d, struct ibevent_file_info, d);

	/* XXX: All this code is bullshit and must be rewritten. There simply
	 * should not be a static variable. */
	static int count = 0;
	if (count > 0) {
		struct ibv_comp_channel *comp_channel;

		pr_debug("Restoring comp_channel object %p fd %d\n", IBCONTEXT, IBCONTEXT->cmd_fd);
		comp_channel = ibv_create_comp_channel(IBCONTEXT);
		if (!comp_channel) {
			pr_err("Failed to restore comp_channel: %d %s\n", IBCONTEXT->cmd_fd, strerror(errno));
			return -1;
		}

		pr_debug("Restored comp_channel fd %d\n", comp_channel->fd);
		int flags = fcntl(comp_channel->fd, F_GETFL, 0);
		fcntl(comp_channel->fd, F_SETFL, flags | O_NONBLOCK);

		*new_fd = comp_channel->fd;
		return 0;
	}
	count++;

	tmp = ibevent();
	if (tmp < 0) {
		pr_perror("Can't create eventfd %#08x",
			  info->ibe->id);
		return -1;
	}

	/* if (rst_file_params(tmp, info->ibe->fown, info->ibe->flags)) { */
	/* 	pr_perror("Can't restore params on ibevent %#08x", */
	/* 		  info->ibe->id); */
	/* 	goto err_close; */
	/* } */

	pr_debug("opened ibevent: id %d fd %d\n", d->id, tmp);
	IBCONTEXT->cmd_fd = 16;
	*new_fd = tmp;
	return 0;

 /* err_close: */
	close(tmp);
	return -1;
}

static struct file_desc_ops ibevent_desc_ops = {
	.type = FD_TYPES__IBEVENTFD,
	.open = ibevent_open,
};

static int collect_one_ibevent(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct ibevent_file_info *info = obj;

	info->ibe = pb_msg(msg, IbeventEntry);
	pr_info_ibevent("Collected", info->ibe);
	int ret = file_desc_add(&info->d, info->ibe->id, &ibevent_desc_ops);
	pr_info("Collected %d\n", ret);
	return ret;
}

struct collect_image_info ibe_cinfo = {
	.fd_type = CR_FD_IBEVENT,
	.pb_type = PB_IBEVENT,
	.priv_size = sizeof(struct ibevent_file_info),
	.collect = collect_one_ibevent,
};
