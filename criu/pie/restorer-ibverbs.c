#include <infiniband/kern-abi.h>
#include <rdma/rdma_user_rxe.h>
#include <kernel-abi/rdma_user_rxe.h>

DECLARE_DRV_CMD(urxe_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		empty, rxe_create_cq_resp);
DECLARE_DRV_CMD(urxe_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		empty, rxe_create_qp_resp);
DECLARE_DRV_CMD(urxe_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		empty, rxe_create_srq_resp);
DECLARE_DRV_CMD(urxe_modify_srq, IB_USER_VERBS_CMD_MODIFY_SRQ,
		rxe_modify_srq_cmd, empty);
DECLARE_DRV_CMD(urxe_resize_cq, IB_USER_VERBS_CMD_RESIZE_CQ,
		empty, rxe_resize_cq_resp);

#include "restore-ibverbs.h"

int ibv_cmd_reg_mr(int ctx_handle, int pd_handle,
		   uintptr_t addr, size_t length,
		   uint64_t hca_va, int access,
		   struct ibv_reg_mr *cmd,
		   size_t cmd_size,
		   struct ibv_reg_mr_resp *resp, size_t resp_size)
{
	int ret;

	cmd->start 	  = addr;
	cmd->length 	  = length;
	/* On demand access and entire address space means implicit.
	 * In that case set the value in the command to what kernel expects.
	 */
	if (access & IBV_ACCESS_ON_DEMAND) {
		if (length == SIZE_MAX && addr)
			return EINVAL;
		if (length == SIZE_MAX)
			cmd->length = UINT64_MAX;
	}

	cmd->hca_va 	  = hca_va;
	cmd->pd_handle 	  = pd_handle;
	cmd->access_flags = access;

	ret = execute_cmd_write(ctx_handle, IB_USER_VERBS_CMD_REG_MR, cmd,
				cmd_size, resp, resp_size);
	if (ret)
		return ret;

	return 0;
}

int rst_ibv_reg_mr(struct rst_ibverbs_object_mr *rmr)
{
	/* XXX: dirty hack to ensure the same lkey */
	int i = 300;
	while (1) {
		struct ibv_reg_mr cmd;
		struct ibv_reg_mr_resp resp;
		int ret = ibv_cmd_reg_mr(rmr->ctx_handle, rmr->pd_handle,
				     rmr->start, rmr->length, rmr->hca_va, rmr->access,
				     &cmd, sizeof cmd, &resp, sizeof resp);
		if (ret) {
			return -1;
		}

		if (rmr->lkey != resp.lkey || rmr->rkey != resp.rkey) {
			pr_err("Unexpected lkey %d (expect %d) or rkey %d (expect %d)\n",
			       resp.lkey, rmr->lkey, resp.rkey, rmr->rkey);
			if (i-- == 0) {
				pr_err("Too many trials\n");
				return -1;
			}

			/* ibv_dereg_mr(mr); */
			return -1;
			continue;
		}

		return 0;
	}

	return -1;
}
