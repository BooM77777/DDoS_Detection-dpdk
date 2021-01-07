#include "featureUpdateCore.h"
#include "feature.h"

void updateFeatureFromHashToHash(struct rte_hash* src, struct rte_hash* dst){
	
    // 创建键
	struct Key* key;
    struct Feature *feature_src, *feature_dst;
 
    // 遍历src哈希表
    uint32_t next = 0;
    uint32_t ret = 0, find = 0;

    // RTE_LOG(INFO, DPDKCAP, "feature updatecore feature size = %d\n", rte_hash_count(src));
    
    for(;;) {

        ret = rte_hash_iterate(src, &key, &feature_src, &next);
        if(ret == -ENOENT) {
            // 哈希表遍历到结尾
            break;
        }
        if(feature_src == NULL){
            continue;
        }
        find = rte_hash_lookup_data(dst, key, &feature_dst);    // 从哈希表中查找该键是否存在
        if(find == -ENOENT || feature_dst == NULL){
            //  如果查找不到，直接插入
            rte_hash_add_key_data(dst, key, feature_src);
        }else{
            // 否则，更新
            combineFeatures(feature_src, feature_dst);
        }
    }
    rte_hash_reset(src);
}

int FeatureUpdate(struct FeatureUpdateCoreConfig* config){

	RTE_LOG(INFO, DPDKCAP, "lcore %u 用于特征的异步转移\n", config->lcore);

    int i, j;
    struct rte_hash *src_hash_table, *dst_hash_table;
    uint8_t atk_type;


    config->isRunning = true;

    // 核心逻辑为，每过一段时间，将
    for(;;){

        if(unlikely(!config->isRunning)) {
            break;
        }

        // 目前的数据转换为及时进行
        // sleep(0.2);
        // RTE_LOG(INFO, DPDKCAP, "config->num_featureExtractCore = %d || config->num_ddosDetectCore = %d \n", config->num_featureExtractCore, config->num_ddosDetectCore);
        for(i = 0; i < config->num_ddosDetectCore; i++){
            
            dst_hash_table = config->ddosDetectCoreList[i]->featureTable;
            atk_type = config->ddosDetectCoreList[i]->atkType;

            for(j = 0; j < config->num_featureExtractCore; j++){

                // 当前特征提取核心没有提取到足够的特征，则跳过当前核心
                // 这么设计的目的是为了减少特征转换核心的处理次数
                // if(config->featureExtractCoreList[j]->pktCnt < config->pktNum_threshold){
                //     continue;
                // }

                src_hash_table = config->featureExtractCoreList[j]->featureTableList[atk_type];
                updateFeatureFromHashToHash(src_hash_table, dst_hash_table);
            }
        }
    }
    
    return 0;
}
