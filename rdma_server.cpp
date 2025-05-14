#include <byteswap.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <netdb.h>
#include <inttypes.h>
#include <sys/time.h>

#define MAX_POLL_CQ_TIMEOUT 4000
#define MSG_SIZE 4096 // 缓冲区大小

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

/* structure of test parameters */
struct config_t
{
	const char *dev_name; /* IB device name */
	char *server_name;	/* server host name */
	u_int32_t tcp_port;   /* server TCP port */
	int ib_port;		  /* local IB port to work with */
	int gid_idx;		  /* gid index to use */
};
/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t
{
	uint64_t addr;   /* Buffer address */
	uint32_t rkey;   /* Remote key */
	uint32_t qp_num; /* QP number */
	uint16_t lid;	/* LID of the IB port */
	uint8_t gid[16]; /* gid */
} __attribute__((packed));

struct resources
{
    struct ibv_device_attr device_attr; /* Device attributes */
    struct ibv_port_attr port_attr; /* IB port attributes */
    struct cm_con_data_t remote_props; /* Remote RDMA infos */
    struct ibv_context *ib_ctx; /* device handle ??*/
    struct ibv_pd *pd; /* PD handle */
    struct ibv_cq *cq; /* CQ handle */
    struct ibv_qp *qp; /* QP handle */
    struct ibv_mr *mr; /* memory region */
    char *buf; /* memory buffer */
    int sock; /* TCP socket file descriptor */
};

static struct config_t config = {
    .dev_name   = nullptr,
    .server_name = nullptr,
    .tcp_port   = 20079,
    .ib_port    = 1,
    .gid_idx    = -1
};

int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data)
{
	int rc;
	int read_bytes = 0;
	int total_read_bytes = 0;
	rc = write(sock, local_data, xfer_size);
	if (rc < xfer_size)
		fprintf(stderr, "Failed writing data during sock_sync_data\n");
	else
		rc = 0;
	while (!rc && total_read_bytes < xfer_size)
	{
		read_bytes = read(sock, remote_data, xfer_size);
		// 打印remote_data
		fprintf(stdout, "remote_data = %s\n", remote_data);
		if (read_bytes > 0) {
			total_read_bytes += read_bytes;
			if (total_read_bytes >= xfer_size)
			{
				struct cm_con_data_t *tmp = (struct cm_con_data_t *)remote_data;
				fprintf(stdout, "远端QP信息： \n remote addr = %lu\n remote rkey = %u\n remote qp num = %u\n remote lid = %u\n",
						tmp->addr, tmp->rkey, tmp->qp_num, tmp->lid);
			}
		}
		else
			rc = read_bytes;
	}
	return rc;
}

static int sock_connect(int port) {
    struct addrinfo *resolved_addr = NULL;
	struct addrinfo *iterator;

    int sockfd = -1;
	int rc = 0;
    struct addrinfo hints =
    {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    rc = getaddrinfo(nullptr, std::to_string(port).c_str(), &hints, &resolved_addr);

    if (rc < 0)
	{
		fprintf(stderr, "%s for %d\n", gai_strerror(sockfd), port);
        freeaddrinfo(resolved_addr);
		return -1;
	}

    for (iterator = resolved_addr; iterator; iterator = iterator->ai_next)
    {
        
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol); // sockfd=3
        fprintf(stdout, "sock_connect: %d\n", sockfd);
        if (sockfd >= 0)
        {
            if (bind(sockfd, iterator->ai_addr, iterator->ai_addrlen))
            {
                close(sockfd);
                sockfd = -1;
            }
            else
            {
                listen(sockfd, 1);
                sockfd = accept(sockfd, NULL, 0);
                fprintf(stdout, "sock_connect: accept %d\n", sockfd);
            }
        }
    }

    freeaddrinfo(resolved_addr);
    return sockfd;
}

static void resources_init(struct resources *res)
{
    memset(res, 0, sizeof(*res));
    res->sock = -1;
    res->buf = nullptr;
    res->mr = nullptr;
    res->cq = nullptr;
    res->pd = nullptr;
    res->qp = nullptr;
    res->ib_ctx = nullptr;
	res->remote_props = {};
	res->remote_props.addr = 0;
	res->remote_props.rkey = 0;
	res->remote_props.qp_num = 0;
	res->remote_props.lid = 0;
	memset(res->remote_props.gid, 0, sizeof(res->remote_props.gid));
}

static int resource_create(struct resources *res)
{
	int rc = 0; // 用于检查函数返回结果
	struct ibv_device **dev_list = nullptr; // IB设备列表
	struct ibv_qp_init_attr qp_init_attr = {}; // QP初始化属性
	struct ibv_device *ib_dev = nullptr; // 选中的IB设备
	size_t size = 0; // 缓冲区大小
	int num_devices = 0; // 设备数量
    int cq_size = 0; // CQ大小

	fprintf(stdout, "waiting on port %d for TCP connection\n", config.tcp_port);

    // 创建TCP连接
    res->sock = sock_connect(config.tcp_port);

    fprintf(stdout, "TCP connection was established\n");
	fprintf(stdout, "searching for IB devices in host\n");


    // 开始获取设备句柄
    dev_list = ibv_get_device_list(&num_devices);

    if (!dev_list)
	{
		fprintf(stderr, "failed to get IB devices list\n");
		rc = 1;
		goto resources_create_exit;
	}
	/* if there isn't any IB device in host */
	if (!num_devices)
	{
		fprintf(stderr, "found %d device(s)\n", num_devices);
		rc = 1;
		goto resources_create_exit;
	}
	fprintf(stdout, "found %d device(s)\n", num_devices);
	/* search for the specific device we want to work with */
	for (int i = 0; i < num_devices; i++)
	{
		if (!config.dev_name)
		{
			config.dev_name = strdup(ibv_get_device_name(dev_list[i]));
			fprintf(stdout, "device not specified, using first one found: %s\n", config.dev_name);
		}
		if (!strcmp(ibv_get_device_name(dev_list[i]), config.dev_name))
		{
			ib_dev = dev_list[i];
			break;
		}
	}

    /* if the device wasn't found in host */
	if (!ib_dev)
	{
		fprintf(stderr, "IB device %s wasn't found\n", config.dev_name);
		rc = 1;
		goto resources_create_exit;
	}
	/* get device handle */
	res->ib_ctx = ibv_open_device(ib_dev);
	if (!res->ib_ctx)
	{
		fprintf(stderr, "failed to open device %s\n", config.dev_name);
		rc = 1;
		goto resources_create_exit;
	}
	/* We are now done with device list, free it */
	ibv_free_device_list(dev_list);
	dev_list = NULL;
	ib_dev = NULL;
    // 获取设备结束

    /* query port properties */
	if (ibv_query_port(res->ib_ctx, config.ib_port, &res->port_attr))
	{
		fprintf(stderr, "ibv_query_port on port %u failed\n", config.ib_port);
		rc = 1;
		goto resources_create_exit;
	}

    // 以下开始分配资源，包括PD、CQ、QP等
    res->pd = ibv_alloc_pd(res->ib_ctx);
    if (!res->pd) {
        fprintf(stderr, "ibv_alloc_pd failed\n");
        rc = 1;
        goto resources_create_exit;
    }

    cq_size = 1;
    res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
    if (!res->cq) {
        fprintf(stderr, "ibv_create_cq failed\n");
        rc = 1;
        goto resources_create_exit;
    }

    size  = MSG_SIZE;
    res->buf = (char *)malloc(size);
    if (!res->buf) {
        fprintf(stderr, "failed to allocate memory\n");
        rc = 1;
        goto resources_create_exit;
    }
    memset(res->buf, 0, size);

    res->mr = ibv_reg_mr(res->pd, res->buf, size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    if (!res->mr) {
        fprintf(stderr, "ibv_reg_mr failed\n");
        rc = 1;
        goto resources_create_exit;
    }
    fprintf(stdout, "memory region was registered with addr=%p, lkey=0x%x, rkey=0x%x\n",
            res->buf, res->mr->lkey, res->mr->rkey);
    /* create the Queue Pair */
    qp_init_attr = {
        .send_cq = res->cq,
        .recv_cq = res->cq,
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 1,
            .max_recv_sge = 1
        },
        .qp_type = IBV_QPT_RC,
        .sq_sig_all = 1,
    };

    // 为QP分配资源，并且指定对应的pd以及cq
    res->qp = ibv_create_qp(res->pd, &qp_init_attr);
    if (!res->qp) {
		fprintf(stderr, "failed to create QP\n");
		rc = 1;
		goto resources_create_exit;
	}
    fprintf(stdout, "QP was created, QP number=0x%x\n", res->qp->qp_num);

resources_create_exit:
	if (rc)
	{
		/* Error encountered, cleanup */
		if (res->qp)
		{
			ibv_destroy_qp(res->qp);
			res->qp = NULL;
		}
		if (res->mr)
		{
			ibv_dereg_mr(res->mr);
			res->mr = NULL;
		}
		if (res->buf)
		{
			free(res->buf);
			res->buf = NULL;
		}
		if (res->cq)
		{
			ibv_destroy_cq(res->cq);
			res->cq = NULL;
		}
		if (res->pd)
		{
			ibv_dealloc_pd(res->pd);
			res->pd = NULL;
		}
		if (res->ib_ctx)
		{
			ibv_close_device(res->ib_ctx);
			res->ib_ctx = NULL;
		}
		if (dev_list)
		{
			ibv_free_device_list(dev_list);
			dev_list = NULL;
		}
		if (res->sock >= 0)
		{
			if (close(res->sock))
				fprintf(stderr, "failed to close socket\n");
			res->sock = -1;
		}
	}
    return rc;
};

static int resources_destroy(struct resources *res)
{
	int rc = 0;
	if (res->qp)
		if (ibv_destroy_qp(res->qp))
		{
			fprintf(stderr, "failed to destroy QP\n");
			rc = 1;
		}
	if (res->mr)
		if (ibv_dereg_mr(res->mr))
		{
			fprintf(stderr, "failed to deregister MR\n");
			rc = 1;
		}
	if (res->buf)
		free(res->buf);
	if (res->cq)
		if (ibv_destroy_cq(res->cq))
		{
			fprintf(stderr, "failed to destroy CQ\n");
			rc = 1;
		}
	if (res->pd)
		if (ibv_dealloc_pd(res->pd))
		{
			fprintf(stderr, "failed to deallocate PD\n");
			rc = 1;
		}
	if (res->ib_ctx)
		if (ibv_close_device(res->ib_ctx))
		{
			fprintf(stderr, "failed to close device context\n");
			rc = 1;
		}
	if (res->sock >= 0)
		if (close(res->sock))
		{
			fprintf(stderr, "failed to close socket\n");
			rc = 1;
		}
	return rc;
}

static int modify_qp_to_init(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	int flags;
	int rc;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = config.ib_port;
	attr.pkey_index = 0;
	attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to INIT\n");
	return rc;
}

static int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid)
{
	struct ibv_qp_attr attr;
	int flags;
	int rc;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = IBV_MTU_256;
	attr.dest_qp_num = remote_qpn;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer = 0x12;
	attr.ah_attr.is_global = 0;
	attr.ah_attr.dlid = dlid;
	attr.ah_attr.sl = 0;
	attr.ah_attr.src_path_bits = 0;
	attr.ah_attr.port_num = config.ib_port;
	if (config.gid_idx >= 0)
	{
		attr.ah_attr.is_global = 1;
		attr.ah_attr.port_num = 1;
		memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
		attr.ah_attr.grh.flow_label = 0;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.sgid_index = config.gid_idx;
		attr.ah_attr.grh.traffic_class = 0;
	}
	flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
			IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to RTR\n");
	return rc;
}
/******************************************************************************
* Function: modify_qp_to_rts
*
* Input
* qp QP to transition
*
* Output
* none
*
* Returns
* 0 on success, ibv_modify_qp failure code on failure
*
* Description
* Transition a QP from the RTR to RTS state
******************************************************************************/
static int modify_qp_to_rts(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	int flags;
	int rc;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 0x12;
	attr.retry_cnt = 6;
	attr.rnr_retry = 0;
	attr.sq_psn = 0;
	attr.max_rd_atomic = 1;
	flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc)
		fprintf(stderr, "failed to modify QP state to RTS\n");
	return rc;
}

static int connect_qp(struct resources *res)
{
    int rc = 0;
    union ibv_gid my_gid;
    char temp_char;
    
    struct cm_con_data_t local_con_data;
	struct cm_con_data_t remote_con_data;
	struct cm_con_data_t tmp_con_data = {
		.addr = 0,
		.rkey = 0,
		.qp_num = 0,
		.lid = 0,
		.gid = {0}
	};

    memset(&my_gid, 0, sizeof my_gid);

    /* 使用TCP socket 通信，交换连接QP的信息*/
    local_con_data.addr = htonll((uintptr_t)res->buf);
	local_con_data.rkey = htonl(res->mr->rkey);
	local_con_data.qp_num = htonl(res->qp->qp_num);
	local_con_data.lid = htons(res->port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);

    fprintf(stdout, "本地QP信息： \n local addr = %lu"  "\n" "local rkey = %u\n local qp num = %u\n local lid = %u\n", local_con_data.addr, local_con_data.rkey, local_con_data.qp_num, local_con_data.lid);

	sock_sync_data(res->sock, 5, "hello", (char *)&tmp_con_data);

    if (sock_sync_data(res->sock, sizeof(struct cm_con_data_t), (char *)&local_con_data, (char *)&tmp_con_data) < 0)
	{
		fprintf(stderr, "failed to exchange connection data between sides\n");
		rc = 1;
		goto connect_qp_exit;
	}

    // remote_con_data.addr = tmp_con_data.addr;
	// remote_con_data.rkey = tmp_con_data.rkey;
	// remote_con_data.qp_num = tmp_con_data.qp_num;
	// remote_con_data.lid = tmp_con_data.lid;
	remote_con_data.addr = ntohll(tmp_con_data.addr);
	remote_con_data.rkey = ntohl(tmp_con_data.rkey);
	remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
	remote_con_data.lid = ntohs(tmp_con_data.lid);
	memcpy(remote_con_data.gid, tmp_con_data.gid, 16);
	/* save the remote side attributes, we will need it for the post SR */
	res->remote_props = remote_con_data;

	fprintf(stdout, "Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);
	fprintf(stdout, "Remote rkey = 0x%x\n", remote_con_data.rkey);
	fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
	fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);

    /* modify the QP to init */
	rc = modify_qp_to_init(res->qp);
	if (rc)
	{
		fprintf(stderr, "change QP state to INIT failed\n");
		goto connect_qp_exit;
	}

    /* modify the QP to RTR */
	rc = modify_qp_to_rtr(res->qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid);
	if (rc)
	{
		fprintf(stderr, "failed to modify QP state to RTR\n");
		goto connect_qp_exit;
	}
	rc = modify_qp_to_rts(res->qp);
	if (rc)
	{
		fprintf(stderr, "failed to modify QP state to RTS\n");
		goto connect_qp_exit;
	}
	fprintf(stdout, "QP state was change to RTS\n");
	/* sync to make sure that both sides are in states that they can connect to prevent packet loose */
	if (sock_sync_data(res->sock, 1, "Q", &temp_char)) /* just send a dummy char back and forth */
	{
		fprintf(stderr, "sync error after QPs are were moved to RTS\n");
		rc = 1;
	}

connect_qp_exit:
	return rc;
}

static int poll_completion(struct resources *res)
{
	struct ibv_wc wc;
	unsigned long start_time_msec;
	unsigned long cur_time_msec;
	struct timeval cur_time;
	int poll_result;
	int rc = 0;
	/* poll the completion for a while before giving up of doing it .. */
	gettimeofday(&cur_time, NULL);
	start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
	do
	{
		poll_result = ibv_poll_cq(res->cq, 1, &wc);
		gettimeofday(&cur_time, NULL);
		cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
	} while ((poll_result == 0) && ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT));
	if (poll_result < 0)
	{
		/* poll CQ failed */
		fprintf(stderr, "poll CQ failed\n");
		rc = 1;
	}
	else if (poll_result == 0)
	{ /* the CQ is empty */
		fprintf(stderr, "completion wasn't found in the CQ after timeout\n");
		rc = 1;
	}
	else
	{
		/* CQE found */
		fprintf(stdout, "completion was found in CQ with status 0x%x\n", wc.status);
		/* check the completion status (here we don't care about the completion opcode */
		if (wc.status != IBV_WC_SUCCESS)
		{
			// 打印wc.status，他是一个枚举类型

			fprintf(stderr, "got bad completion with status: %d, vendor syndrome: 0x%x\n", wc.status,
					wc.vendor_err);
			rc = 1;
		}
	}
	return rc;
}

static int post_send(struct resources *res, ibv_wr_opcode opcode)
{
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;
    int rc;
    
    /* prepare the scatter/gather entry */
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)res->buf;
    sge.length = strlen(res->buf) + 1;  // 使用实际消息长度
    sge.lkey = res->mr->lkey;
    
    fprintf(stdout, "准备发送消息: %s, 长度: %d\n", res->buf, sge.length);
    
    /* prepare the send work request */
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = opcode;
    sr.send_flags = IBV_SEND_SIGNALED;
    
    if (opcode != IBV_WR_SEND)
    {
        sr.wr.rdma.remote_addr = res->remote_props.addr;
        sr.wr.rdma.rkey = res->remote_props.rkey;
    }
    
    rc = ibv_post_send(res->qp, &sr, &bad_wr);
    if (rc)
    {
        fprintf(stderr, "failed to post SR, error: %d\n", rc);
    }
    else
    {
        switch (opcode)
        {
        case IBV_WR_SEND:
            fprintf(stdout, "Send Request was posted successfully\n");
            break;
        case IBV_WR_RDMA_READ:
            fprintf(stdout, "RDMA Read Request was posted\n");
            break;
        case IBV_WR_RDMA_WRITE:
            fprintf(stdout, "RDMA Write Request was posted\n");
            break;
        default:
            fprintf(stdout, "Unknown Request was posted\n");
            break;
        }
    }
    return rc;
}
/******************************************************************************
* Function: post_receive
*
* Input
* res pointer to resources structure
*
* Output
* none
*
* Returns
* 0 on success, error code on failure
*
* Description
*
******************************************************************************/
static int post_receive(struct resources *res)
{
	struct ibv_recv_wr rr;
	struct ibv_sge sge;
	struct ibv_recv_wr *bad_wr;
	int rc;
	/* prepare the scatter/gather entry */
	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)res->buf;
	sge.length = MSG_SIZE;
	sge.lkey = res->mr->lkey;
	/* prepare the receive work request */
	memset(&rr, 0, sizeof(rr));
	rr.next = NULL;
	rr.wr_id = 0;
	rr.sg_list = &sge;
	rr.num_sge = 1;
	/* post the Receive Request to the RQ */
	rc = ibv_post_recv(res->qp, &rr, &bad_wr);
	if (rc)
		fprintf(stderr, "failed to post RR\n");
	else
		fprintf(stdout, "Receive Request was posted\n");
	return rc;
}


int main() {
    struct resources res;
    int rc = 1;
	char temp_char;
	char* server_msg = "Server send msg";

    resources_init(&res);
    rc = resource_create(&res);

    if (rc) {
        fprintf(stderr, "failed to create resources\n");
        goto main_exit;
    }

    // 连接QP

    rc = connect_qp(&res);

	/* 发起一次SEND/RECV */
	strcpy(res.buf, "[server]: ");

	if (post_send(&res, IBV_WR_SEND))
	{
		fprintf(stderr, "failed to post sr\n");
		goto main_exit;
	}

	fprintf(stdout, "send msg: %s\n", res.buf);

	
	if (poll_completion(&res))
	{
		fprintf(stderr, "poll completion failed\n");
		goto main_exit;
	}

	
	// strcpy(res.buf, "server_msg");

	/* Sync so we are sure server side has data ready before client tries to read it */
	// if (sock_sync_data(res.sock, 1, "R", &temp_char)) /* just send a dummy char back and forth */
	// {
	// 	fprintf(stderr, "sync error before RDMA ops\n");
	// 	rc = 1;
	// 	goto main_exit;
	// }


main_exit:
	if (resources_destroy(&res))
	{
		fprintf(stderr, "failed to destroy resources\n");
		rc = 1;
	}
	if (config.dev_name)
		free((char *)config.dev_name);
	fprintf(stdout, "\ntest result is %d\n", rc);
	return rc;
    return 0;
}
