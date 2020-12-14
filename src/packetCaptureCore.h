#ifndef PACKETCAPTURECORE
#define PACKETCAPTURECORE

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

struct PacketCaptureCoreConfig{
    
    // dpdk参数
    uint16_t port;
    lcore_id lcore;
    queue_id queue;

    struct rte_ring* ring;

    // 控制线程
    uint8_t isRunning;
};

int PacketCapture(struct PacketCaptureCoreConfig* config);  // 数据包抓取的核心逻辑

#endif
