/* This works only with SoftRoCE (rxe) */

#include <stdint.h>
#include <stddef.h>
#include <linux/types.h>

#include "types.h"
#include "criu-log.h"
#include "restore-ibverbs.h"

#include <infiniband/verbs.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/rdma_user_rxe.h>
#include <rdma/ib_user_ioctl_cmds.h>

struct ibv_reg_mr {
	struct ib_uverbs_cmd_hdr hdr;
	union {
		struct {
			__aligned_u64 response;
			__aligned_u64 start;
			__aligned_u64 length;
			__aligned_u64 hca_va;
			__u32 pd_handle;
			__u32 access_flags;
			__aligned_u64 driver_data[0];
		};
		struct ib_uverbs_reg_mr core_payload;
	};
};

struct ibv_dereg_mr {
	struct ib_uverbs_cmd_hdr hdr;
	union {
		struct {
			__u32 command;
			__u16 in_words;
			__u16 out_words;
			__u32 mr_handle;
		};
		struct ib_uverbs_dereg_mr core_payload;
	};
};

struct ibv_create_cq {
	struct ib_uverbs_cmd_hdr hdr;
	union {
		struct {
			__u32 command;
			__u16 in_words;
			__u16 out_words;
			__u64 response;
			__u64 user_handle;
			__u32 cqe;
			__u32 comp_vector;
			__s32 comp_channel;
			__u32 reserved;
			__u64 driver_data[0];
		};
		struct ib_uverbs_create_cq core_payload;
	};
};

struct ibv_command_buffer {
	struct ibv_command_buffer *next;
	struct ib_uverbs_attr *next_attr;
	struct ib_uverbs_attr *last_attr;
	/*
	 * Used by the legacy write interface to keep track of where the UHW
	 * buffer is located and the 'headroom' space that the common code
	 * uses to construct the command header and common command struct
	 * directly before the drivers' UHW.
	 */
	uint8_t uhw_in_idx;
	uint8_t uhw_out_idx;
	uint8_t uhw_in_headroom_dwords;
	uint8_t uhw_out_headroom_dwords;

	uint8_t buffer_error:1;
	/*
	 * These flags control what execute_ioctl_fallback does if the kernel
	 * does not support ioctl
	 */
	uint8_t fallback_require_ex:1;
	uint8_t fallback_ioctl_only:1;
	struct ib_uverbs_ioctl_hdr hdr;
};

enum {_UHW_NO_INDEX = 0xFF};

/*
 * Constructing an array of ibv_command_buffer is a reasonable way to expand
 * the VLA in hdr.attrs on the stack and also allocate some internal state in
 * a single contiguous stack memory region. It will over-allocate the region in
 * some cases, but this approach allows the number of elements to be dynamic,
 * and not fixed as a compile time constant.
 */
#define _IOCTL_NUM_CMDB(_num_attrs)                                            \
	((sizeof(struct ibv_command_buffer) +                                  \
	  sizeof(struct ib_uverbs_attr) * (_num_attrs) +                       \
	  sizeof(struct ibv_command_buffer) - 1) /                             \
	 sizeof(struct ibv_command_buffer))

unsigned int __ioctl_final_num_attrs(unsigned int num_attrs,
				     struct ibv_command_buffer *link);

/* If the user doesn't provide a link then don't create a VLA */
#define _ioctl_final_num_attrs(_num_attrs, _link)                              \
	((__builtin_constant_p(!(_link)) && !(_link))                          \
		 ? (_num_attrs)                                                \
		 : __ioctl_final_num_attrs(_num_attrs, _link))

#define _COMMAND_BUFFER_INIT(_hdr, _object_id, _method_id, _num_attrs, _link)  \
	((struct ibv_command_buffer){                                          \
		.hdr =                                                         \
			{                                                      \
				.object_id = (_object_id),                     \
				.method_id = (_method_id),                     \
			},                                                     \
		.next = _link,                                                 \
		.uhw_in_idx = _UHW_NO_INDEX,                                   \
		.uhw_out_idx = _UHW_NO_INDEX,                                  \
		.next_attr = (_hdr).attrs,                                     \
		.last_attr = (_hdr).attrs + _num_attrs})

/*
 * C99 does not permit an initializer for VLAs, so this function does the init
 * instead. It is called in the wonky way so that DELCARE_COMMAND_BUFFER can
 * still be a 'variable', and we so we don't require C11 mode.
 */
static inline int _ioctl_init_cmdb(struct ibv_command_buffer *cmd,
				   uint16_t object_id, uint16_t method_id,
				   size_t num_attrs,
				   struct ibv_command_buffer *link)
{
	*cmd = _COMMAND_BUFFER_INIT(cmd->hdr, object_id, method_id, num_attrs,
				    link);
	return 0;
}

/*
 * Construct an IOCTL command buffer on the stack with enough space for
 * _num_attrs elements. _num_attrs does not have to be a compile time constant.
 * _link is a previous COMMAND_BUFFER in the call chain.
 */
/*
 * sparse enforces kernel rules which forbids VLAs. Make the VLA into a static
 * array when running sparse. Don't actually run the sparse compile result.
 */
#define DECLARE_COMMAND_BUFFER_LINK(_name, _object_id, _method_id, _num_attrs, \
				    _link)				\
	struct ibv_command_buffer _name[10];				\
	int __attribute__((unused)) __##_name##dummy =			\
		_ioctl_init_cmdb(_name, _object_id, _method_id, 10, _link)

#define DECLARE_COMMAND_BUFFER(_name, _object_id, _method_id, _num_attrs) \
	DECLARE_COMMAND_BUFFER_LINK(_name, _object_id, _method_id, _num_attrs, \
				    NULL)

#define DECLARE_FBCMD_BUFFER DECLARE_COMMAND_BUFFER_LINK

/*
 * This macro is used to implement the compatibility command call wrappers.
 * Compatibility calls do not accept a command_buffer, and cannot use the new
 * attribute id mechanism. They accept the legacy kern-abi.h structs that have
 * the embedded header.
 */
void _write_set_uhw(struct ibv_command_buffer *cmdb, const void *req,
                    size_t core_req_size, size_t req_size, void *resp,
                    size_t core_resp_size, size_t resp_size);
#define DECLARE_CMD_BUFFER_COMPAT(_name, _object_id, _method_id, cmd,          \
                                  cmd_size, resp, resp_size)                   \
        DECLARE_COMMAND_BUFFER(_name, _object_id, _method_id, 2);              \
        _write_set_uhw(_name, cmd, sizeof(*cmd), cmd_size, resp,               \
                       sizeof(*resp), resp_size)

static inline uint64_t ioctl_ptr_to_u64(const void *ptr)
{
	if (sizeof(ptr) == sizeof(uint64_t))
		return (uintptr_t)ptr;

	/*
	 * Some CPU architectures require sign extension when converting from
	 * a 32 bit to 64 bit pointer.  This should match the kernel
	 * implementation of compat_ptr() for the architecture.
	 */
#if defined(__tilegx__)
	return (int64_t)(intptr_t)ptr;
#else
	return (uintptr_t)ptr;
#endif
}

static inline struct ib_uverbs_attr *
_ioctl_next_attr(struct ibv_command_buffer *cmd, uint16_t attr_id)
{
	struct ib_uverbs_attr *attr;

	if (cmd->next_attr >= cmd->last_attr)
		pr_err("Failure");
	attr = cmd->next_attr++;

	*attr = (struct ib_uverbs_attr){
		.attr_id = attr_id,
		/*
		 * All attributes default to mandatory. Wrapper the fill_*
		 * call in attr_optional() to make it optional.
		 */
		.flags = UVERBS_ATTR_F_MANDATORY,
	};

	return attr;
}

static inline uint32_t read_attr_obj(uint16_t attr_id,
                                     struct ib_uverbs_attr *attr)
{
        return attr->data;
}

/* Send attributes of kernel type UVERBS_ATTR_TYPE_PTR_IN */
static inline struct ib_uverbs_attr *
fill_attr_in(struct ibv_command_buffer *cmd, uint16_t attr_id, const void *data,
	     size_t len)
{
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	if (unlikely(len > UINT16_MAX))
		cmd->buffer_error = 1;

	attr->len = len;
	if (len <= sizeof(uint64_t))
		memcpy(&attr->data, data, len);
	else
		attr->data = ioctl_ptr_to_u64(data);

	return attr;
}

static inline struct ib_uverbs_attr *
fill_attr_in_uint64(struct ibv_command_buffer *cmd, uint16_t attr_id,
		    uint64_t data)
{
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	attr->len = sizeof(data);
	attr->data = data;

	return attr;
}

/* Send attributes of kernel type UVERBS_ATTR_TYPE_IDR */
static inline struct ib_uverbs_attr *
fill_attr_in_obj(struct ibv_command_buffer *cmd, uint16_t attr_id, uint32_t idr)
{
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	/* UVERBS_ATTR_TYPE_IDR uses a 64 bit value for the idr # */
	attr->data = idr;
	return attr;
}

static inline struct ib_uverbs_attr *
fill_attr_out_obj(struct ibv_command_buffer *cmd, uint16_t attr_id)
{
        return fill_attr_in_obj(cmd, attr_id, 0);
}

#define fill_attr_const_in(cmd, attr_id, _data)		\
	fill_attr_in_uint64(cmd, attr_id, _data)

/* Send attributes of kernel type UVERBS_ATTR_TYPE_PTR_OUT */
static inline struct ib_uverbs_attr *
fill_attr_out(struct ibv_command_buffer *cmd, uint16_t attr_id, void *data,
	      size_t len)
{
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	if (unlikely(len > UINT16_MAX))
		cmd->buffer_error = 1;

	attr->len = len;
	attr->data = ioctl_ptr_to_u64(data);

	return attr;
}

#define fill_attr_out_ptr(cmd, attr_id, ptr)                                 \
        fill_attr_out(cmd, attr_id, ptr, sizeof(*(ptr)))

static inline struct ib_uverbs_attr *
fill_attr_in_uint32(struct ibv_command_buffer *cmd, uint16_t attr_id,
                    uint32_t data)
{
        struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

        attr->len = sizeof(data);
        memcpy(&attr->data, &data, sizeof(data));

        return attr;
}

static inline struct ib_uverbs_attr *
fill_attr_in_fd(struct ibv_command_buffer *cmd, uint16_t attr_id, int fd)
{
        struct ib_uverbs_attr *attr;

        if (fd == -1)
                return NULL;

        attr = _ioctl_next_attr(cmd, attr_id);
        /* UVERBS_ATTR_TYPE_FD uses a 64 bit value for the idr # */
        attr->data = fd;
        return attr;
}

/*
 * This bitmask indicate the required behavior of execute_ioctl_fallback when
 * the ioctl is not supported. It is a priority list where the highest set bit
 * takes precedence. This approach simplifies the typical required control
 * flow of the user.
 */
static inline void fallback_require_ex(struct ibv_command_buffer *cmdb)
{
        cmdb->fallback_require_ex = 1;
}

static void prepare_attrs(struct ibv_command_buffer *cmd)
{
	struct ib_uverbs_attr *end = cmd->next_attr;
	struct ibv_command_buffer *link;

	for (link = cmd->next; link; link = link->next) {
		struct ib_uverbs_attr *cur;

		if ((cmd->hdr.object_id != link->hdr.object_id) ||
		    (cmd->hdr.method_id != link->hdr.method_id))
			pr_err("Failure");

		/*
		 * Keep track of where the uhw_in lands in the final array if
		 * we copy it from a link
		 */
		if (link->uhw_in_idx != _UHW_NO_INDEX) {
			if(cmd->uhw_in_idx != _UHW_NO_INDEX)
				pr_err("Failure!");
			cmd->uhw_in_idx =
				link->uhw_in_idx + (end - cmd->hdr.attrs);
		}

		for (cur = link->hdr.attrs; cur != link->next_attr; cur++)
			*end++ = *cur;

		if (end > cmd->last_attr)
			pr_err("Failure!");
	}

	cmd->hdr.num_attrs = end - cmd->hdr.attrs;

	/*
	 * We keep the in UHW uninlined until directly before sending to
	 * support the compat path. See _fill_attr_in_uhw
	 */
	if (cmd->uhw_in_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw = &cmd->hdr.attrs[cmd->uhw_in_idx];

		if (!(uhw->attr_id == UVERBS_ATTR_UHW_IN))
			pr_err("Failure!");

		if (uhw->len <= sizeof(uhw->data))
			memcpy(&uhw->data, (void *)(uintptr_t)uhw->data,
			       uhw->len);
	}
}

/*
 * Copy the link'd attrs back to their source and ignore valgrind.
 */
static void finalize_attrs(struct ibv_command_buffer *cmd)
{
	struct ibv_command_buffer *link;
	struct ib_uverbs_attr *end;

	for (end = cmd->hdr.attrs; end != cmd->next_attr; end++);

	for (link = cmd->next; link; link = link->next) {
		struct ib_uverbs_attr *cur;

		for (cur = link->hdr.attrs; cur != link->next_attr; cur++) {
			*cur = *end++;
		}
	}
}

/*
 * The compat scheme for UHW IN requires a pointer in .data, however the
 * kernel protocol requires pointers < 8 to be inlined into .data. We defer
 * that transformation until directly before the ioctl.
 */
static inline struct ib_uverbs_attr *
_fill_attr_in_uhw(struct ibv_command_buffer *cmd, uint16_t attr_id,
                 const void *data, size_t len)
{
        struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

        if (unlikely(len > UINT16_MAX))
                cmd->buffer_error = 1;

        attr->len = len;
        attr->data = ioctl_ptr_to_u64(data);

        return attr;
}

/*
 * This helper is used in the driver compat wrappers to build the
 * command buffer from the legacy input pointers format.
 */
void _write_set_uhw(struct ibv_command_buffer *cmdb, const void *req,
                    size_t core_req_size, size_t req_size, void *resp,
                    size_t core_resp_size, size_t resp_size)
{
        if (req && core_req_size < req_size) {
		cmdb->uhw_in_idx =
			_fill_attr_in_uhw(cmdb, UVERBS_ATTR_UHW_IN,
					  (uint8_t *)req +
					  core_req_size,
					  req_size - core_req_size) -
			cmdb->hdr.attrs;
                cmdb->uhw_in_headroom_dwords = core_req_size / 4;
        }


        if (resp && core_resp_size < resp_size) {
                cmdb->uhw_out_idx =
                        fill_attr_out(cmdb, UVERBS_ATTR_UHW_OUT,
                                      (uint8_t *)resp + core_resp_size,
                                      resp_size - core_resp_size) -
                        cmdb->hdr.attrs;
                cmdb->uhw_out_headroom_dwords =
                        core_resp_size / 4;
        }
}

static int execute_ioctl(int ctx_handle, struct ibv_command_buffer *cmd)
{
	/*
	 * One of the fill functions was given input that cannot be marshaled
	 */
	if (unlikely(cmd->buffer_error)) {
		return EINVAL;
	}

	prepare_attrs(cmd);
	cmd->hdr.length = sizeof(cmd->hdr) +
		sizeof(cmd->hdr.attrs[0]) * cmd->hdr.num_attrs;
	cmd->hdr.reserved1 = 0;
	cmd->hdr.reserved2 = 0;
	cmd->hdr.driver_id = RDMA_DRIVER_RXE;

	int ret = sys_ioctl(ctx_handle, RDMA_VERBS_IOCTL, (unsigned long)&cmd->hdr);
	if (ret < 0)
		return ret;

	finalize_attrs(cmd);

	return 0;
}

static int ioctl_write(int ctx_handle, unsigned int write_method,
		       const void *req, size_t core_req_size, size_t req_size,
		       void *resp, size_t core_resp_size, size_t resp_size)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DEVICE,
			       UVERBS_METHOD_INVOKE_WRITE, 5);

	fill_attr_const_in(cmdb, UVERBS_ATTR_WRITE_CMD, write_method);

	if (core_req_size)
		fill_attr_in(cmdb, UVERBS_ATTR_CORE_IN, req, core_req_size);
	if (core_resp_size)
		fill_attr_out(cmdb, UVERBS_ATTR_CORE_OUT, resp, core_resp_size);

	if (req_size - core_req_size)
		fill_attr_in(cmdb, UVERBS_ATTR_UHW_IN, req + core_req_size,
			     req_size - core_req_size);
	if (resp_size - core_resp_size)
		fill_attr_out(cmdb, UVERBS_ATTR_UHW_OUT, resp + core_resp_size,
			      resp_size - core_resp_size);

	return execute_ioctl(ctx_handle, cmdb);
}

static int execute_cmd_write(int ctx_handle, unsigned int write_method,
		      struct ib_uverbs_cmd_hdr *req, size_t core_req_size,
		      size_t req_size, void *resp, size_t core_resp_size,
		      size_t resp_size)
{
	return ioctl_write(ctx_handle, write_method, req + 1,
			   core_req_size - sizeof(*req),
			   req_size - sizeof(*req), resp,
			   core_resp_size, resp_size);
}


int ibv_cmd_reg_mr(int ctx_handle, int pd_handle,
		   uintptr_t addr, size_t length,
		   uint64_t hca_va, int access,
		   struct ibv_reg_mr *cmd,
		   size_t cmd_size,
		   struct ib_uverbs_reg_mr_resp *resp, size_t resp_size)
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

	cmd->core_payload.response = (uintptr_t)resp;
	ret = execute_cmd_write(ctx_handle, IB_USER_VERBS_CMD_REG_MR,
		&(cmd)->hdr, sizeof(*(cmd)), cmd_size,
		resp, sizeof(*(resp)), resp_size);
	if (ret)
		return ret;

	return 0;
}



int ibv_cmd_dereg_mr(int ctx_handle, int mr_handle)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_MR, UVERBS_METHOD_MR_DESTROY,
			     1, NULL);
	int ret;

	fill_attr_in_obj(cmdb, UVERBS_ATTR_DESTROY_MR_HANDLE,
			 mr_handle);

	ret = execute_ioctl(ctx_handle, cmdb);

	if (ret == EIO)
		return ret;
	return 0;
}

int rst_ibv_reg_mr(struct rst_ibverbs_object_mr *rmr)
{
	/* XXX: dirty hack to ensure the same lkey */
	int i = 300;
	while (1) {
		struct ibv_reg_mr cmd;
		struct ib_uverbs_reg_mr_resp resp;
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

			ret = ibv_cmd_dereg_mr(rmr->ctx_handle, resp.mr_handle);
			if (ret) {
				pr_err("Dereg failed\n");
				return -1;
			}
			continue;
		}

		return 0;
	}

	return -1;
}

static int ibv_icmd_create_cq(int ctx_handle, int cqe,
			      int channel_handle, int comp_vector,
			      uint32_t flags, struct ibv_cq *cq,
			      struct ibv_command_buffer *link)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_CQ, UVERBS_METHOD_CQ_CREATE, 7, link);
	struct ib_uverbs_attr *handle;
	uint32_t resp_cqe;
	int ret;

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_CREATE_CQ_HANDLE);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_CQ_RESP_CQE, &resp_cqe);

	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_CQ_CQE, cqe);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_CREATE_CQ_USER_HANDLE, (uintptr_t)cq);
	if (channel_handle != -1)
		fill_attr_in_fd(cmdb, UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL, channel_handle);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_CQ_COMP_VECTOR, comp_vector);

	if (flags) {
		fallback_require_ex(cmdb);
		fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_CQ_FLAGS, flags);
	}

	ret = execute_ioctl(ctx_handle, cmdb);
	if (ret) {
		pr_err("Failed create_cq IOCTL\n");
		return ret;
	}
	cq->handle = read_attr_obj(UVERBS_ATTR_CREATE_CQ_HANDLE, handle);
	cq->cqe = resp_cqe;

	return 0;
}


int ibv_cmd_create_cq(int ctx_handle, int cqe,
		      int channel_handle, int comp_vector,
		      struct ibv_cq *cq, struct ibv_create_cq *cmd,
		      size_t cmd_size, struct ib_uverbs_create_cq_resp *resp,
		      size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_CQ,
				  UVERBS_METHOD_CQ_CREATE, cmd, cmd_size, resp,
				  resp_size);

	return ibv_icmd_create_cq(ctx_handle, cqe, channel_handle, comp_vector,
				  0, cq, cmdb);
}

int rst_ibv_create_cq(struct rst_ibverbs_object_cq *rcq)
{
	/* XXX: Need to do it here, to ensure that CQ created after creating
	 * MR. */
	struct ib_uverbs_create_cq_resp resp;
	struct ibv_cq cq;

	int ret = ibv_cmd_create_cq(rcq->ctx_handle, rcq->cqe,
				    rcq->comp_channel, rcq->comp_vector,
				    &cq, NULL, 0,
				    &resp, sizeof(resp));
	if (ret) {
		return -1;
	}

	return 0;
}
