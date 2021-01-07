#include "ddosDetectCore.h"
#include "container.h"
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
    uint32_t atk_ip_cnt;                    // 攻击IP个数
    uint32_t* ip_list;                      // IP列表
    float* pkt_cnt_pre_ip;                  // 每个IP的报文个数
    float* pkt_entropy_pre_ip;              // 每个IP的长度熵值

    uint8_t* vote_res;                      // 投票的结果
};

struct HistoricalData{
    /* data */
    struct Container* container_totalPktCnt;
    struct Container* container_ipEntropy;
    struct Container* container_pktCntPreIP;
};

static bool detectionByTotalPktCnt(struct Container* c, struct FeatureCollection* featureCollection) {

    getBound(c, BOUND_TYPE_MAX);
    
    return c->upperBound < featureCollection->total_pkt_cnt;
}

static bool detectionByIPEntropy(struct Container* c, struct FeatureCollection* featureCollection) {

    getBound(c, BOUND_TYPE_MEAN);

    return featureCollection->total_ip_entropy < c->lowerBound || featureCollection->total_ip_entropy > c->upperBound;
}

static bool detectionByPktCntPerIP(struct Container* c, struct FeatureCollection * featureCollection) {

    bool ret = false;

    getBound(c, BOUND_TYPE_MAX);

    for(uint32_t i = 0; i < featureCollection->total_ip_cnt; i++) {
        if(featureCollection->pkt_cnt_pre_ip[i] > c->upperBound) {
            featureCollection->vote_res[i]++;
            ret = true;
        }
    }

    return ret;
}

static bool attackDection(struct HistoricalData *historicalData, struct FeatureCollection *featureCollection) {
    
    //检测是否存在疑似攻击检测
    if(detectionByTotalPktCnt(historicalData->container_totalPktCnt, featureCollection) == false) {
        if(detectionByTotalPktCnt(historicalData->container_ipEntropy, featureCollection) == false) {
            return false;
        }
    }
    
    // 否则，窗口内存在DDoS攻击
    return detectionByPktCntPerIP(historicalData->container_pktCntPreIP, featureCollection);
}

static void updateHistoricalDataWithoutCheck(struct HistoricalData *historicalData, struct FeatureCollection *featureCollection) {
    
    addDataToContainer(historicalData->container_totalPktCnt, featureCollection->total_pkt_cnt);

    addDataToContainer(historicalData->container_ipEntropy,
        entropy(featureCollection->pkt_cnt_pre_ip, featureCollection->total_ip_cnt));

    addDataToContainer(historicalData->container_pktCntPreIP, 
        mean(featureCollection->pkt_cnt_pre_ip, featureCollection->total_ip_cnt));
}

static void updateHistoricalData(struct HistoricalData *historicalData, struct FeatureCollection *featureCollection) {
    
    int totalPktCnt = 0;
    
    int total_ip_cnt = 0;
    uint32_t* pkt_cnt_pre_ip = malloc(MAX_IP_PRE_WIN);

    for(int i = 0; i < featureCollection->total_ip_cnt; i++) {
        if(featureCollection->vote_res[i] == 0) {

            totalPktCnt += featureCollection->pkt_cnt_pre_ip[i];

            pkt_cnt_pre_ip[i] = featureCollection->pkt_cnt_pre_ip[i];
            total_ip_cnt++;
        }
    }
    addDataToContainer(historicalData->container_totalPktCnt, totalPktCnt);

    addDataToContainer(historicalData->container_ipEntropy, entropy(pkt_cnt_pre_ip, total_ip_cnt));

    addDataToContainer(historicalData->container_pktCntPreIP, mean(pkt_cnt_pre_ip, total_ip_cnt));
}

static void collect_feature(struct DDoSDetectCoreConfig *config, struct FeatureCollection *feature_collection) {
    
    int ret = 0;

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
    uint32_t find = 0;
    int j;

    for(;;) {
        ret = rte_hash_iterate(config->featureTable, &k, &f, &next);
        if(ret == -ENOENT) {
            break;
        }
        
        feature_collection->total_pkt_cnt += f->pkt_cnt;
        for(j = 0; j < PAYLOAD_INTERVAL_BIN_NUM; j++){
            feature_collection->total_pkt_len_distribution[j] += f->payload_len_bin[j];
        }

        feature_collection->ip_list[feature_collection->total_ip_cnt] = k->aimIP;
        feature_collection->pkt_cnt_pre_ip[feature_collection->total_ip_cnt] = f->pkt_cnt;
        feature_collection->pkt_entropy_pre_ip[feature_collection->total_ip_cnt] = getPayloadEntropy(f);
        
        feature_collection->total_ip_cnt++;
    }

    feature_collection->total_ip_entropy
        = entropy(feature_collection->pkt_cnt_pre_ip, feature_collection->total_ip_cnt);
    feature_collection->total_pkt_len_entropy
        = entropy(feature_collection->total_pkt_len_distribution, PAYLOAD_INTERVAL_BIN_NUM);

    rte_hash_reset(config->featureTable);
}

static void WriterResToLogFile(struct FeatureCollection* featureCollection, FILE* logfile) {

    uint8_t* ip;

    fprintf(logfile, "{atk_ip_cnt:%u, ", featureCollection->atk_ip_cnt);
    fprintf(logfile, "atk_ip_list:[");
    for(int i = 0; i < featureCollection->total_pkt_cnt; i++) {
        if(featureCollection->vote_res[i] > 0) {
            ip = convertIPFromUint32(featureCollection->ip_list[i]);
            fprintf(logfile, "%s %u.%u.%u.%u", (i == 0 ? "" : ","), ip[0], ip[1], ip[2], ip[3]);
        }
    }
    fprintf(logfile, ",]}\n");

    fflush(logfile);
}

static void WriteDebugInfoToLogFile(struct HistoricalData* historicalData, FILE* debugfile) {

    fprintf(debugfile, "{total_pkt_cnt : {upperbound : %.6f}",
        historicalData->container_totalPktCnt->upperBound);
    fprintf(debugfile, "{ipEntropy : {upperbound : %.6f, lowerbound : %.6f}",
        historicalData->container_ipEntropy->upperBound, historicalData->container_ipEntropy->lowerBound);
    fprintf(debugfile, "pkt_cnt_per_ip : {upperbound : %.6f}}",
        historicalData->container_pktCntPreIP->upperBound);

    fflush(debugfile);
}

int DDoSDetect(struct DDoSDetectCoreConfig* config){

	RTE_LOG(INFO, DPDKCAP, "lcore %u 用于 %s 攻击检测\n", config->lcore, config->name);
    int ret;
    int i;
    uint8_t init_progress = 0; // 初始化进度，用于记录初始化的下标
    char* ip;


    FILE* debugfile = fopen(config->fileName_debug, "wb");
    FILE* logfile = fopen(config->fileName_log, "wb");
    

    // 用于存储特征的数据结构
    struct FeatureCollection* feature_collection = malloc(sizeof(struct FeatureCollection));
    if(feature_collection == NULL) {
        rte_exit(EXIT_FAILURE, "featurecollection 创建失败!\n");
    }

    feature_collection->total_pkt_len_distribution = malloc(PAYLOAD_INTERVAL_BIN_NUM);
    feature_collection->ip_list = malloc(MAX_IP_PRE_WIN);
    feature_collection->pkt_cnt_pre_ip = malloc(MAX_IP_PRE_WIN);
    feature_collection->pkt_entropy_pre_ip = malloc(MAX_IP_PRE_WIN);
    feature_collection->vote_res = malloc(MAX_IP_PRE_WIN);

    // 用于存储历史数据的数据结构
    struct HistoricalData* historicalData = malloc(sizeof(struct HistoricalData));
    if(historicalData == NULL) {
        rte_exit(EXIT_FAILURE, "historicalData 创建失败!\n");
    }

    historicalData->container_totalPktCnt = malloc(sizeof(struct Container));
    initContainer(historicalData->container_totalPktCnt, MAX_INIT_PROGRESS);
    historicalData->container_ipEntropy = malloc(sizeof(struct Container));
    initContainer(historicalData->container_ipEntropy, MAX_INIT_PROGRESS);
    historicalData->container_pktCntPreIP = malloc(sizeof(struct Container));
    initContainer(historicalData->container_pktCntPreIP, MAX_INIT_PROGRESS);

    config->isRunning = true;

    for(;;){

        // 结束条件
        if(unlikely(!(config->isRunning))){
            break;
        }

        // 窗口延迟
        sleep(config->detectionWinSize);
        collect_feature(config, feature_collection);
        printf("一共收到了%d个IP的%d个数据包。\n",
            feature_collection->total_ip_cnt, feature_collection->total_pkt_cnt);

        if(unlikely(feature_collection->total_ip_cnt <= 0)) {
            continue;
        }
        
        if(unlikely(init_progress < MAX_INIT_PROGRESS)){
            // 初始化
            init_progress++;
            updateHistoricalDataWithoutCheck(historicalData, feature_collection);
            
        }else{
            // 攻击检测
            if(attackDection(historicalData, feature_collection)){
                RTE_LOG(INFO, DPDKCAP, "发现DDoS攻击，共有%d个攻击IP：\n", feature_collection->atk_ip_cnt);
                for(int i = 0; i < feature_collection->total_ip_cnt; i++) {
                    if(feature_collection->vote_res[i] > 0) {
                        ip = convertIPFromUint32(feature_collection->ip_list[i]);
                        RTE_LOG(INFO, DPDKCAP, "\t%s\n", ip);
                    }
                }

                // WriterResToLogFile(feature_collection, logfile);
                // WriteDebugInfoToLogFile(historicalData, debugfile);
            }
            updateHistoricalData(historicalData, feature_collection);
        }
    }

     //fclose(logfile);
     //fclose(debugfile);

    return 0;
}