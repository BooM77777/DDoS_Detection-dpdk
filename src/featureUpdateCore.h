#ifndef FEATURE_UPDATE_CORE
#define FEATURE_UPDATE_CORE

#include "rte_log.h"
#include "rte_hash.h"

#include "stdint.h"
#include "unistd.h"

#include "util.h"
#include "common.h"

#include "featureExtractCore.h"
#include "ddosDetectCore.h"
#include "stdbool.h"

struct FeatureUpdateCoreConfig{
    
    // dpdk参数
    lcore_id lcore;

    uint8_t feature_update_win;
    uint32_t pktNum_threshold;

    uint16_t num_featureExtractCore;
    struct FeatureExtractCoreConfig** featureExtractCoreList;

    uint16_t num_ddosDetectCore;
    struct DDoSDetectCoreConfig** ddosDetectCoreList;

    // 控制线程
    bool isRunning;
};

int FeatureUpdate(struct FeatureUpdateCoreConfig* config);  // 数据包抓取的核心逻辑

#endif