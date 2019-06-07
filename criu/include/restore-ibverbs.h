#ifndef __CR_RESTORER_IBVERBS_H__
#define __CR_RESTORER_IBVERBS_H__

#include "ibverbs.h"
#include "restorer.h"

int rst_ibv_reg_mr(struct rst_ibverbs_object_mr *mr);

#endif /* __CR_RESTORER_IBVERBS_H__ */
