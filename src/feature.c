#include "feature.h"

struct Key* getKey(uint32_t aimIP){
    struct Key* ret = (struct Key*)malloc(sizeof(struct Key));
    ret->aimIP = aimIP;
    return ret;
}

// 创建一个空的特征（所有特征都置0），用于替代构造函数
struct Feature* createEmptyFeature(){
    struct Feature* ret = (struct Feature*)malloc(sizeof(struct Feature));
    ret->pkt_cnt = 0;
    for(int i = 0; i < PAYLOAD_INTERVAL_BIN_NUM; i++){
        ret->payload_len_bin[i] = 0;
    }
    return ret; 
}
struct Feature* createFeature(uint16_t payload_len){
    
    struct Feature* ret = createEmptyFeature();
    combineFeatureWithLength(ret, payload_len);
    return ret;
}

void combineFeatureWithLength(struct Feature* aim, uint16_t payload_len){

    aim->pkt_cnt++;
    aim->payload_len_bin[payload_len / PAYLOAD_INTERVAL_SIZE]++;
}

float getPayloadEntropy(const struct Feature* f){
    return entropy(f->payload_len_bin, PAYLOAD_INTERVAL_BIN_NUM);
}

// 合并两个Feature，将结果保存在dstfeature中int
void combineFeatures(struct Feature* src, struct Feature* dst){

    dst->pkt_cnt += src->pkt_cnt;
    for(int i = 0; i < PAYLOAD_INTERVAL_BIN_NUM; i++){
        dst->payload_len_bin[i] += src->payload_len_bin[i];
    }
    
    return 0;
}