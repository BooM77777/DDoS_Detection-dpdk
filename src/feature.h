#ifndef FEATURE_H
#define FEATURE_H

#include "stdint.h"
#include "util.h"
#include "common.h"

struct Key{
    uint32_t aimIP;
};

struct Key* getKey(uint32_t aimIP);

struct Feature{

    uint32_t pkt_cnt;           // 记录包个数
    uint32_t payload_len_bin[PAYLOAD_INTERVAL_BIN_NUM];  // 记录有效载荷分布
};

// 创建一个空的特征（所有特征都置0），用于替代构造函数
struct Feature* createEmptyFeature();
struct Feature* createFeature(uint16_t payload_len);

float getPayloadEntropy(const struct Feature* f);

// 合并两个Feature，将结果保存在dstfeature中int
void combineFeatures(struct Feature* src, struct Feature* dst);
void combineFeatureWithLength(struct Feature* aim, uint16_t payload_len);

#endif