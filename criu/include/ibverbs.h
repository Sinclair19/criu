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

#endif
