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

static struct ibv_device* find_ibdev(const char *ib_devname)
{
	int num_of_device;
	struct ibv_device **dev_list;
	struct ibv_device *ib_dev = NULL;

	dev_list = ibv_get_device_list(&num_of_device);

	if (num_of_device <= 0) {
		pr_err(" Did not detect devices. If device exists, check if driver is up.\n");
		return NULL;
	}

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

static int dump_one_ibverbs_pd(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_pd *dump_pd;
	IbverbsPd *pd;

	dump_pd = container_of(dump_obj, struct ib_uverbs_dump_object_pd, obj);

	pr_err("Found object PD: %d\n", dump_pd->obj.handle);

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

static int dump_one_ibverbs_mr(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj,
			       struct vm_area_list *vmas)
{
	struct ib_uverbs_dump_object_mr *dump_mr;
	IbverbsMr *mr;

	dump_mr = container_of(dump_obj, struct ib_uverbs_dump_object_mr, obj);
	pr_err("Found object MR: %d @0x%llx + 0x%llx\n", dump_mr->obj.handle, dump_mr->address, dump_mr->length);

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

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__MR;
	(*pb_obj)->handle = dump_mr->obj.handle;
	(*pb_obj)->mr = mr;

	struct vma_area *vma, *p;
	list_for_each_entry_safe(vma, p, &vmas->h, list) {
		if ((vma->e->end < mr->address) ||
		    (mr->address + mr->length < vma->e->start)) {
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

	pr_err("Found object CQ: %d\n", dump_cq->obj.handle);

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		return -1;
	}
	ibverbs_object__init(*pb_obj);
	cq = xmalloc(sizeof(*cq));
	if (!cq) {
		xfree(*pb_obj);
		return -1;
	}
	ibverbs_cq__init(cq);

	cq->cqe = dump_cq->cqe;
	cq->comp_channel = dump_cq->comp_channel;
	cq->vm_start = dump_cq->vm_start;
	cq->vm_size = dump_cq->vm_size;
	cq->comp_vector = dump_cq->comp_vector;

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__CQ;
	(*pb_obj)->handle = dump_cq->obj.handle;
	(*pb_obj)->cq = cq;

	return sizeof(*dump_cq);
}

static int dump_one_ibverbs_qp(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_qp *dump_qp;
	IbverbsQp *qp;

	dump_qp = container_of(dump_obj, struct ib_uverbs_dump_object_qp, obj);

	pr_err("Found object QP: %d\n", dump_qp->obj.handle);

	*pb_obj = xmalloc(sizeof(**pb_obj));
	if (!*pb_obj) {
		return -1;
	}
	ibverbs_object__init(*pb_obj);
	qp = xmalloc(sizeof(*qp));
	if (!qp) {
		xfree(*pb_obj);
		return -1;
	}
	ibverbs_qp__init(qp);

	qp->pd_handle = dump_qp->pd_handle;
	qp->qp_type = dump_qp->qp_type;
	qp->srq_handle = dump_qp->srq_handle;
	qp->sq_sig_all = dump_qp->sq_sig_all;

	qp->rq_start = dump_qp->rq_start;
	qp->rq_size = dump_qp->rq_size;
	qp->rcq_handle = dump_qp->rcq_handle;

	qp->scq_handle = dump_qp->scq_handle;
	qp->sq_start = dump_qp->sq_start;
	qp->sq_size = dump_qp->sq_size;

	qp->max_send_wr = dump_qp->attr.cap.max_send_wr;
	qp->max_recv_wr = dump_qp->attr.cap.max_recv_wr;
	qp->max_send_sge = dump_qp->attr.cap.max_send_sge;
	qp->max_recv_sge = dump_qp->attr.cap.max_recv_sge;
	qp->max_inline_data = dump_qp->attr.cap.max_inline_data;

	(*pb_obj)->type = IBVERBS_OBJECT_TYPE__QP;
	(*pb_obj)->handle = dump_qp->obj.handle;
	(*pb_obj)->qp = qp;

	return sizeof(*dump_qp);
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
	const char *ib_devname = "rxe0";
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
	const unsigned int dump_size = 4096;
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

	pr_err("Found total Objs: %d\n", count);

	ibv.n_objs = count;
	ibv.objs = xzalloc(pb_repeated_size(&ibv, objs));

	if (!ibv.objs) {
		pr_err("Failed to allocate memory for protection domains\n");
		goto out;
	}

	void *cur_obj = dump;
	for (int i = 0; i < count; i++) {
		struct ib_uverbs_dump_object *obj = cur_obj;
		pr_err("Found obj of type: %d %p %p %d\n", obj->type, cur_obj, obj, *(uint32_t *)cur_obj);
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
		default:
			pr_err("Unknown object type: %d\n", obj->type);
			ret = -1;
			break;
		}
		if (ret < 0) {
			goto out;
		}
		pr_err("Moving pointer by %d\n", ret);
		cur_obj += ret;
	}

	img = img_from_set(glob_imgset, CR_FD_FILES);
	ret = pb_write_one(img, &fe, PB_FILE);
	if (ret) {
		pr_perror("Failed to write image\n");
	}

 out:
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

#define ELEM_COUNT 10
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

static int ibverbs_restore_pd(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	struct ibv_context *ibcontext = entry->ibcontext;
	IbverbsObject *obj = entry->obj;
	struct ibv_pd *pd;
	pd = ibv_alloc_pd(ibcontext);
	if (!pd) {
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

	pr_err("Restored PD object %d\n", obj->handle);
	return 0;

 err:
	ibv_dealloc_pd(pd);
	return -1;
}

static int ibverbs_restore_mr(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	IbverbsObject *obj = entry->obj;
	IbverbsMr *pb_mr = obj->mr;

	/* XXX: dirty hack to ensure the same lkey */
	int i = 300;
	while (1) {
		struct ibv_mr *mr;
		struct ibv_pd *pd;

		pd = ibverbs_get_object(IB_UVERBS_OBJECT_PD, pb_mr->pd_handle);
		if (!pd) {
			pr_err("PD object with id %d is not known\n", pb_mr->pd_handle);
			return -1;
		}

		mr = ibv_reg_mr(pd, (void *)pb_mr->address, pb_mr->length, pb_mr->access);
		if (!mr) {
			pr_err("ibv_reg_mr failed: %s\n", strerror(errno));
			return -1;
		}

		if (pb_mr->lkey != mr->lkey || pb_mr->rkey != mr->rkey) {
			pr_err("Unexpected lkey %d (expect %d) or rkey %d (expect %d)\n",
			       mr->lkey, pb_mr->lkey, mr->rkey, pb_mr->rkey);
			if (i-- == 0) {
				pr_err("Too many trials\n");
				return -1;
			}

			int ret = ibv_dereg_mr(mr);
			if (ret) {
				pr_err("Dereg failed\n");
				return -1;
			}
			continue;
		}

		if (ibverbs_remember_object(IB_UVERBS_OBJECT_MR, mr->handle, mr)) {
			pr_err("Failed to remember object\n");
			return -1;
		}

		pr_err("Restored MR object %d\n", obj->handle);
		return 0;
	}
}

static int ibverbs_restore_cq(struct ibverbs_list_entry *entry, struct task_restore_args *ta)
{
	IbverbsObject *obj = entry->obj;
	IbverbsCq *cq = obj->cq;

	if (cq->comp_channel != -1) {
		pr_err("BBBSHSTHSHT\n");
		return -1;
	}

	struct ibv_restore_object_cq args;

	args.cqe = cq->cqe;
	args.queue.vm_start = cq->vm_start;
	args.queue.vm_size = cq->vm_size;
	args.comp_vector = cq->comp_vector;
	args.channel = NULL;

	int ret = ibv_restore_object(entry->ibcontext, IB_UVERBS_OBJECT_CQ, &args);
	if (ret < 0) {
		pr_err("Failed to create CQ\n");
		return -1;
	}

	if (args.queue.vm_size > 0) {
		if (keep_address_range((u64)args.queue.vm_start, args.queue.vm_size))
			return -1;
	}

	if (ibverbs_remember_object(IB_UVERBS_OBJECT_CQ, args.cq->handle, args.cq)) {
		pr_err("Failed to remember CQ object with id %d\n", args.cq->handle);
		return -1;
	}

	pr_err("Restored CQ object %d\n", obj->handle);
	return 0;
}

static int ibverbs_restore_qp(struct ibverbs_list_entry * entry, struct task_restore_args *ta)
{
	IbverbsObject *obj = entry->obj;
	IbverbsQp *qp = obj->qp;

	struct ibv_restore_object_qp args;

	args.pd = ibverbs_get_object(IB_UVERBS_OBJECT_PD, qp->pd_handle);
	if (!args.pd) {
		pr_err("Failed to find PD object with id: %d\n", qp->pd_handle);
		return -1;
	}

	args.attr.send_cq = ibverbs_get_object(IB_UVERBS_OBJECT_CQ, qp->scq_handle);
	if (!args.attr.send_cq) {
		pr_err("Failed to find PD object with id: %d\n", qp->scq_handle);
		return -1;
	}

	args.attr.recv_cq = ibverbs_get_object(IB_UVERBS_OBJECT_CQ, qp->rcq_handle);
	if (!args.attr.recv_cq) {
		pr_err("Failed to find PD object with id: %d\n", qp->rcq_handle);
		return -1;
	}

	if (qp->srq_handle != UINT32_MAX) {
		pr_err("SRQs are not supported: %x\n", qp->scq_handle);
		return -ENOTSUP;
	}

	args.attr.qp_context = NULL;
	args.attr.srq = NULL;
	args.attr.qp_type = qp->qp_type;
	args.attr.sq_sig_all = qp->sq_sig_all;

	args.attr.cap.max_send_wr = qp->max_send_wr;
	args.attr.cap.max_recv_wr = qp->max_recv_wr;
	args.attr.cap.max_send_sge = qp->max_send_sge;
	args.attr.cap.max_recv_sge = qp->max_recv_sge;
	args.attr.cap.max_inline_data = qp->max_inline_data;

	args.rq.vm_start = qp->rq_start;
	args.rq.vm_size = qp->rq_size;

	args.sq.vm_start = qp->sq_start;
	args.sq.vm_size = qp->sq_size;

	int ret = ibv_restore_object(entry->ibcontext, IB_UVERBS_OBJECT_QP, &args);
	if (ret < 0) {
		pr_err("Failed to restore QP\n");
		return -1;
	}

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

	pr_err("Restored QP object %d\n", obj->handle);
	return 0;
}

static int ibverbs_open(struct file_desc *d, int *new_fd)
{
	struct ibverbs_file_info *info;
	struct ibv_device *ibdev;
	struct ibv_context *ibcontext;
	const char *ib_devname = "rxe0";

	info = container_of(d, struct ibverbs_file_info, d);

	pr_info("Opening device %s", ib_devname);
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
	pr_err("Opened device: cmd_fd %d async_fd %d file_desc->id %d\n",
	       ibcontext->cmd_fd, ibcontext->async_fd, d->id);

	if (rst_file_params(ibcontext->cmd_fd, info->ibv->fown, info->ibv->flags)) {
		pr_perror("Can't restore params on ibverbs %#08x\n",
			  info->ibv->id);
		goto err_close;
	}

	pr_err("Available objects for the context: %ld\n", info->ibv->n_objs);

	/* The reverse order of objects in the list is important, because the
	 * dump we get first has MR, then PD */
	for (int i = 0; i < info->ibv->n_objs ; i++) {
		struct ibverbs_list_entry *le = xzalloc(sizeof(*le));

		le->ibdev = ibdev;
		le->ibcontext = ibcontext;
		le->obj = info->ibv->objs[i];

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
		default:
			pr_err("Object type is not supported: %d\n", le->obj->type);
			goto err_close;
		}
		list_add(&le->restore_list, &ibverbs_restore_objects);
	}

	pr_info("Opened a device %d %d", ibcontext->cmd_fd, ibcontext->async_fd);
	last_event_fd = ibcontext->async_fd;

	*new_fd = ibcontext->cmd_fd;
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

	pr_err("Found ibverbs area 0x%08lx - 0x%08lx tgt 0x%08lx Anon %d, FD %ld\n", vma->e->start, vma->e->end, vma->premmaped_addr,
	       vma->e->flags & MAP_ANONYMOUS, vma->e->fd);

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

	ta->ibverbs = (struct rst_ibverbs_object *)rst_mem_align_cpos(RM_PRIVATE);
	ta->ibverbs_n = 0;

	int i = 0;
	list_for_each_entry(le, &ibverbs_restore_objects, restore_list) {
		pr_err("Restoring object %d of type %d\n", i++, le->obj->type);
		int ret = le->restore(le, ta);
		if (ret < 0) {
			pr_err("Failed to restore object of type: %d\n", le->obj->type);
			return -1;
		}
	}

	return 0;
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

	pr_err("opened ibevent: id %d fd %d\n", d->id, tmp);
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
