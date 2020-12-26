#ifndef DDOS_DETECTION_CORE_H
#define DDOS_DETECTION_CORE_H

#include "common.h"
#include "packetCaptureCore.h"

#include "rte_hash.h"
#include "rte_log.h"

#include "stdbool.h"

#define MAX_PC_CORE_NUM 256 // 攻击检测核心中引用的最大的特征提取核心个数

struct DDoSDetectCoreConfig{
    
    lcore_id lcore;

    uint8_t atkType;                // 用于标记攻击类型

    const char* name;
    const char* fileName_log;  // 用于存储受攻击IP的文件
    const char* fileName_debug;   // 用于存储阈值的文件

    bool isRunning;               // 控制线程的关闭
    uint8_t detectionWinSize;       // 用于设置检测窗口大小

    struct rte_hash* featureTable; // 特征表
};

int DDoSDetect(struct DDoSDetectCoreConfig* config);

#endif
