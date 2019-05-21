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

	img = img_from_set(glob_imgset, CR_FD_FILES);
	return pb_write_one(img, &fe, PB_FILE);
}

const struct fdtype_ops ibverbs_dump_ops = {
	.type	= FD_TYPES__IBVERBS,
	.dump	= dump_one_ibverbs,
};

static int last_event_fd;

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
