#ifndef __CR_IBVERBS_H__
#define __CR_IBVERBS_H__

#include <linux/major.h>

#include "files.h"

extern const struct fdtype_ops ibverbs_dump_ops;
extern const struct fdtype_ops ibevent_dump_ops;

extern int is_ibevent_link(char *link);

struct ibverbs_driver;
struct ibverbs_driver *get_ibverbs_driver(dev_t rdev, dev_t dev);
static inline int is_ibverbs(dev_t rdev, dev_t dev)
{
	return get_ibverbs_driver(rdev, dev) != NULL;
}

extern struct collect_image_info ibv_cinfo;
extern struct collect_image_info ibe_cinfo;

struct task_restore_args;
int prepare_ibverbs(struct task_restore_args *ta);

int collect_ibverbs_area(struct vma_area *vma);

enum rst_ibverbs_object_type {
	RST_IBVERBS_INVALID = 0,
	RST_IBVERBS_MR = 1,
	RST_IBVERBS_CQ = 2,
};

struct rst_ibverbs_object_mr {
	uintptr_t	start;
	uint64_t	hca_va;
	size_t		length;
	int		ctx_handle;
	int		pd_handle;
	int		access;
	int		lkey;
	int		rkey;
	int		handle;
};

struct rst_ibverbs_object_cq {
	int ctx_handle;
	int cqe;
	int comp_channel;
	int comp_vector;
	int handle;
};

struct rst_ibverbs_object {
	unsigned int type;
	union {
		struct rst_ibverbs_object_mr mr;
		struct rst_ibverbs_object_cq cq;
	};
};

#endif
