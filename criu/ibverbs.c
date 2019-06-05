#include <infiniband/verbs.h>

#include "files.h"
#include "fdinfo.h"
#include "files-reg.h"
#include "imgset.h"
#include "ibverbs.h"

#include "protobuf.h"
#include "images/ibverbs.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "ibverbs: "

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

static int dump_one_ibverbs_mr(IbverbsObject **pb_obj, struct ib_uverbs_dump_object *dump_obj)
{
	struct ib_uverbs_dump_object_mr *dump_mr;
	IbverbsMr *mr;

	dump_mr = container_of(dump_obj, struct ib_uverbs_dump_object_mr, obj);
	pr_err("Found object MR: %d\n", dump_mr->obj.handle);

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

	return sizeof(*dump_mr);

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

	int ret;
	int count;
	char dump[256];
	ret = ibv_dump_context(ctx, &count, dump, sizeof(dump));
	if (ret) {
		pr_err("Failed to dump protection domain: %d\n", ret);
		return -1;
	}

	ibv.n_objs = count;
	ibv.objs = xzalloc(pb_repeated_size(&ibv, objs));

	if (!ibv.objs) {
		pr_err("Failed to allocate memory for protection domains\n");
		return -1;
	}

	pr_err("Found total Objs: %d\n", count);

	void *cur_obj = dump;
	for (int i = 0; i < count; i++) {
		struct ib_uverbs_dump_object *obj = cur_obj;
		pr_err("Found obj of type: %d %p %p %d\n", obj->type, cur_obj, obj, *(uint32_t *)cur_obj);
		switch(obj->type) {
		case IB_UVERBS_OBJECT_PD:
			ret = dump_one_ibverbs_pd(&ibv.objs[i], obj);
			break;
		case IB_UVERBS_OBJECT_MR:
			ret = dump_one_ibverbs_mr(&ibv.objs[i], obj);
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
	for (int i = 0; i < count; i++) {
		xfree(ibv.objs[i]);
	}
	xfree(ibv.objs);
	return ret;
}

const struct fdtype_ops ibverbs_dump_ops = {
	.type	= FD_TYPES__IBVERBS,
	.dump	= dump_one_ibverbs,
};

#define ELEM_COUNT 10
static int last_event_fd;
static struct ibv_pd *open_pds[ELEM_COUNT];
static struct ibv_mr *open_mrs[ELEM_COUNT];

static int ibverbs_restore_pd(struct ibv_context *ibcontext, IbverbsObject *obj)
{
	struct ibv_pd *pd;
	pd = ibv_alloc_pd(ibcontext);
	if (!pd) {
		return -1;
	}

	if (pd->handle != obj->handle) {
		pr_err("Unexpected protection domain handle: %d vs %d\n", obj->handle, pd->handle);
		ibv_dealloc_pd(pd);
		return -1;
	}

	open_pds[pd->handle] = pd;

	return 0;
}

static int ibverbs_restore_mr(IbverbsObject *obj)
{
	IbverbsMr *pb_mr = obj->mr;
	struct ibv_pd *pd = open_pds[pb_mr->pd_handle];
	struct ibv_mr *mr;
#define TRACE 1
#if TRACE
	int fd = open("/sys/kernel/debug/tracing/tracing_on", O_WRONLY);
	write(fd, "1", 1);
#endif
	mr = ibv_reg_mr(pd, (void *)pb_mr->address, pb_mr->length, pb_mr->access);
#if TRACE
	write(fd, "0", 1);
	close(fd);
#endif
	if (!mr) {
		pr_err("Failed to register memory region (0x%lx, +0x%lx) at PD %d with flags %x\n",
		       pb_mr->address, pb_mr->length, pb_mr->pd_handle, pb_mr->access);
	}

	pr_err("Registered MR (0x%p, +0x%lx) at PD %d with flags %x: handle %d lkey %d rkey %d\n",
	       mr->addr, mr->length, mr->pd->handle, pb_mr->access, mr->handle, mr->lkey, mr->rkey);

	open_mrs[mr->handle] = mr;

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

	if (rst_file_params(ibcontext->cmd_fd, info->ibv->fown, info->ibv->flags)) {
		pr_perror("Can't restore params on ibverbs %#08x\n",
			  info->ibv->id);
		goto err_close;
	}

	pr_err("Available PDs total: %ld\n", info->ibv->n_objs);

	for (int i = info->ibv->n_objs - 1; i >= 0 ; i--) {
		IbverbsObject *obj = info->ibv->objs[i];
		int ret;

		pr_err("Restoring object %d of type %d\n", i, obj->type);
		switch (obj->type) {
		case IBVERBS_OBJECT_TYPE__PD:
			ret = ibverbs_restore_pd(ibcontext, obj);
			break;
		case IBVERBS_OBJECT_TYPE__MR:
			ret = ibverbs_restore_mr(obj);
			break;
		default:
			pr_err("Object type is not supported: %d\n", obj->type);
			goto err_close;
		}
		if (ret < 0) {
			goto err_close;
		}
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

	pr_info("%s:%d\n", __func__, __LINE__);
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
