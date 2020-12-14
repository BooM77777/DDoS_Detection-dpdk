#include "ddosDetectCore.h"
#include "feature.h"
#include "util.h"

#define MAX_INIT_PROGRESS 10
#define MAX_IP_PRE_WIN 65536

// 用于包含所有的特征
struct FeatureCollection{

    uint32_t total_pkt_cnt;                 // 总包数 
    uint32_t* total_pkt_len_distribution;   // 总报文长度分布

    float total_ip_entropy;                 // 总IP熵
    float total_pkt_len_entropy;            // 总报文长度熵

    uint32_t total_ip_cnt;                  // 总IP个数
    uint32_t* ip_list;                      // IP列表
    uint32_t* pkt_cnt_pre_ip;               // 每个IP的报文个数
    float* pkt_entropy_pre_ip;           // 每个IP的长度熵值

    uint8_t* vote_res;                      // 投票的结果
};

void collect_feature(struct DDoSDetectCoreConfig* config, struct FeatureCollection* feature_collection){

    // 清空数据结构
    feature_collection->total_ip_cnt = 0;
    feature_collection->total_pkt_cnt = 0;
    feature_collection->total_ip_entropy = 0;
    feature_collection->total_pkt_len_entropy = 0;
    memset(feature_collection->total_pkt_len_distribution, 0, PAYLOAD_INTERVAL_BIN_NUM);
    memset(feature_collection->ip_list, 0, MAX_IP_PRE_WIN);
    memset(feature_collection->pkt_cnt_pre_ip, 0, MAX_IP_PRE_WIN);
    memset(feature_collection->pkt_entropy_pre_ip, 0, MAX_IP_PRE_WIN);
    memset(feature_collection->vote_res, 0, MAX_IP_PRE_WIN);

    struct Key* k;
    struct Feature* f;
    
     // 遍历特征表哈希表
    uint32_t next = 0;
    uint32_t ret = 0, find = 0;
    int j;
    for(int i = 0; ret != ENOENT; ret != rte_hash_iterate(config->featureTable, &k, &f, next), i++){

        feature_collection->total_pkt_cnt += f->pkt_cnt;
        for(j = 0; j < PAYLOAD_INTERVAL_BIN_NUM; j++){
            feature_collection->total_pkt_len_distribution[j] += f->payload_len_bin[j];
        }

        feature_collection->ip_list = k->aimIP;
        feature_collection->pkt_cnt_pre_ip[feature_collection->total_ip_cnt] = f->pkt_cnt;
        feature_collection->pkt_entropy_pre_ip[feature_collection->total_ip_cnt] = getPayloadEntropy(f);
        
        feature_collection->total_ip_cnt++;
    }
    feature_collection->total_ip_entropy
        = entropy(feature_collection->pkt_cnt_pre_ip, feature_collection->total_ip_cnt);
    feature_collection->total_pkt_len_entropy
        = entropy(feature_collection->total_pkt_len_distribution, PAYLOAD_INTERVAL_BIN_NUM);
}

int DDoSDetect(struct DDoSDetectCoreConfig* config){

    int ret;
    int i;
    uint8_t init_progress = 0; // 初始化进度，用于记录初始化的下标

    struct FeatureCollection* feature_collection = malloc(sizeof(struct FeatureCollection));

    // 暂时只考虑同时接收65536个IP
    feature_collection->total_pkt_len_distribution = malloc(PAYLOAD_INTERVAL_BIN_NUM);
    feature_collection->ip_list = malloc(MAX_IP_PRE_WIN);
    feature_collection->pkt_cnt_pre_ip = malloc(MAX_IP_PRE_WIN);
    feature_collection->pkt_entropy_pre_ip = malloc(MAX_IP_PRE_WIN);
    feature_collection->vote_res = malloc(MAX_IP_PRE_WIN);

    config->isRunning = true;

	RTE_LOG(INFO, DPDKCAP, "lcore %u 用于 HTTP GET 泛洪攻击检测\n", config->lcore);

    for(;;){
        
        // 结束条件
        if(unlikely(config->isRunning)){
            break;
        }
        // 窗口延迟
        sleep(config->detectionWinSize);

        collect_feature(config, feature_collection);
        printf("一共收到了%d个IP的%d个数据包。\n",
            feature_collection->total_ip_cnt, feature_collection->total_pkt_cnt);

        if(unlikely(init_progress < MAX_INIT_PROGRESS)){
            // 初始化
            // init_seq();
        }else{
            // 攻击检测

        }

    }

    return 0;
}