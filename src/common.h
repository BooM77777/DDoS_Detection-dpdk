#ifndef COMMON_H
#define COMMON_H

#include "rte_ethdev.h"
#include "stdint.h"

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

typedef unsigned int lcore_id;
typedef uint16_t port_id;
typedef uint16_t queue_id;

#define RTE_LOGTYPE_LCORE RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER2

#define FEATURE_HASH_HTTP_GET_FLOOD "Feature Hash Table of HTTP Get Flooding Attack"
#define FEATURE_HASH_HTTP_POST_FLOOD "Feature Hash Table of HTTP Post Flooding Attack"

#define NUMS_ATTACK_DETECTION_CORE_DEFAULT 0
#define NUMS_FEATURE_EXTRACTION_CORE_DEFAULT 1

#define DPDKCAP_CAPTURE_BURST_SIZE 256

#define RX_DESC_DEFAULT 512

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#include "rte_hash.h"
#include "rte_jhash.h"
#include "rte_lcore.h"

#define MAX_CAP_NUM 1
#define MAX_DET_NUM 1

#define MAX_ERR_BUF_LEN 1024


#define ERROR_BUF_LENGTH 1024
#define MAX_PKT_LENGTH 65536
#define MS_INTERVAL_PER_CAPTURE 100

#define GET_SIGN 1
#define POST_SIGN 2

#define MAX_PAYLOAD_LEN 1024
#define PAYLOAD_INTERVAL_SIZE 128
#define PAYLOAD_INTERVAL_BIN_NUM 8

// 攻击类型
#define ATK_TYPE_TOTAL_NUM 6
#define ATK_TYPE_HTTP_GET 0
#define ATK_TYPE_HTTP_POST 1
// #define ATK_TYPE_SSL_CLIENT_KEY_EXCHANGE 2
#define ATK_TYPE_SSL_CLIENT_HELLO 2
#define ATK_TYPE_SSL_APPLICATION_DATA 3
#define ATK_TYPE_DNS_REQUEST 4
#define ATK_TYPE_DNS_REPLY 5

// 攻击检测相关的参数
#define HISTORICAL_DATA_LEN 10
#define BOUND_TYPE_MEAN 0
#define BOUND_TYPE_MAX 1

// 特征提取相关参数
#define POLLING_POLICY_THRESHOLD 1

static struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

// struct rte_hash_patameters feature_tabel_params = {
//   .name = NULL,     // 哈希表表名
//   .entries = 1024,  // 哈希表总条目数
//   .key_len = sizeof(uint32_t),  // 键的长度
//   .hash_func = rte_jhash,   // 使用的哈希算法
//   .hash_func_init_val = 0,  //  哈希算法初始化参数
//   .socket_id = rte_socket_id(),  // 绑定NUMA
// };

#include "feature.h"

#endif
