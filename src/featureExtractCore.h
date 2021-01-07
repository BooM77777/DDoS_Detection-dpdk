#ifndef FEATURE_EXTRACT_CORE
#define FEATURE_EXTRACT_CORE

#include "rte_mbuf.h"
#include "rte_log.h"
#include "rte_ring.h"
#include "rte_hash.h"

#include "stdint.h"
#include "unistd.h"

#include "rte_ethdev.h"

#include "util.h"
#include "common.h"
#include "ddosDetectCore.h"

struct FeatureExtractCoreConfig{
    
    // dpdk参数
    lcore_id lcore;

    struct rte_ring* ring;

    uint64_t pktCnt;    // 用于存储处理了的数据包数量
	// 特征列表
	struct rte_hash** featureTableList;

    // 控制线程
    uint8_t isRunning;
};

// 特征提取的主循环
int FeatureExtract(struct FeatureExtractCoreConfig* config);

#endif
