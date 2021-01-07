#include "stdio.h"
#include "signal.h"
#include "stdint.h"

#include "rte_eal.h"
#include "rte_log.h"
#include "rte_mbuf.h"
#include "rte_lcore.h"
#include "rte_ring.h"
#include "rte_launch.h"
#include "rte_ethdev.h"

#include "packetCaptureCore.h"
#include "featureExtractCore.h"
#include "featureUpdateCore.h"
#include "ddosDetectCore.h"

#include "feature.h"
#include "common.h"

#define	EXIT_FAILURE	1	/* Failing exit status.  */
#define	EXIT_SUCCESS	0	/* Successful exit status.  */

#define RTE_TEST_RX_DESC_DEFAULT 512

#define NUM_MBUFS_DEFAULT 8192
#define MBUF_CACHE_SIZE 256

#define PACKET_RECEIVE_PORTS_NUM 1

#define PACKET_RECEIVE_LCORE_NUM 1
#define FEATURE_EXTRACTION_LCORE_NUM 1
#define DDOS_DETECTION_LCORE_NUM 0

static lcore_id* lcore_list;
static uint8_t nb_lcores;

static struct PacketCaptureCoreConfig** packet_capture_core_list;
static struct FeatureExtractCoreConfig** feature_extract_core_list;

static const struct rte_eth_conf port_conf_default = {
  .rxmode = {
    .mq_mode = ETH_MQ_RX_NONE,
    .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
  }
};


#define FEATURE_TABLE_NAME_FORMAT "feature_table-%d-%s"
static struct rte_hash* CreateFeatureTable(const char* name){

    struct rte_hash_parameters* feature_tabel_params = malloc(sizeof(struct rte_hash_parameters));
    feature_tabel_params->name = name;                      //  哈希表表名
    feature_tabel_params->entries = 8192;                   //  哈希表总条目数
    feature_tabel_params->key_len = sizeof(struct Key);     //  键的长度
    feature_tabel_params->hash_func = rte_jhash;            //  使用的哈希算法
    feature_tabel_params->hash_func_init_val = 0;           //  哈希算法初始化参数
    feature_tabel_params->socket_id = rte_socket_id();
    feature_tabel_params->extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY | RTE_HASH_EXTRA_FLAGS_EXT_TABLE;

    struct rte_hash* featureTable = rte_hash_create(feature_tabel_params);
    return featureTable;	
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static int port_init(
    uint8_t port,
    const uint16_t rx_rings,
    unsigned int num_rxdesc,
    struct rte_mempool *mbuf_pool) {

  struct rte_eth_conf port_conf = port_conf_default;
  struct rte_eth_dev_info dev_info;
  int retval;
  uint16_t q;
  uint16_t dev_count;

  /* Check if the port id is valid */
  dev_count = rte_eth_dev_count_avail()-1;

  if(rte_eth_dev_is_valid_port(port)==0) {
     RTE_LOG(ERR, DPDKCAP, "Port identifier %d out of range (0 to %d) or not"\
       " attached.\n", port, dev_count);
    return -EINVAL;
  }

  /* Get the device info */
  rte_eth_dev_info_get(port, &dev_info);

  /* Check if the requested number of queue is valid */
  if(rx_rings > dev_info.max_rx_queues) {
    RTE_LOG(ERR, DPDKCAP, "Port %d can only handle up to %d queues (%d "\
        "requested).\n", port, dev_info.max_rx_queues, rx_rings);
    return -EINVAL;
  }

  /* Check if the number of requested RX descriptors is valid */
  if(num_rxdesc > dev_info.rx_desc_lim.nb_max ||
     num_rxdesc < dev_info.rx_desc_lim.nb_min ||
     num_rxdesc % dev_info.rx_desc_lim.nb_align != 0) {
    RTE_LOG(ERR, DPDKCAP, "Port %d cannot be configured with %d RX "\
        "descriptors per queue (min:%d, max:%d, align:%d)\n",
        port, num_rxdesc, dev_info.rx_desc_lim.nb_min,
        dev_info.rx_desc_lim.nb_max, dev_info.rx_desc_lim.nb_align);
    return -EINVAL;
  }

  /* Configure multiqueue (Activate Receive Side Scaling on UDP/TCP fields) */
  if (rx_rings > 1) {
    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
  }

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
  if (retval) {
    RTE_LOG(ERR, DPDKCAP, "rte_eth_dev_configure(...): %s\n",
        rte_strerror(-retval));
    return retval;
  }

  /* Allocate and set up RX queues. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, num_rxdesc,
        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval) {
      RTE_LOG(ERR, DPDKCAP, "rte_eth_rx_queue_setup(...): %s\n",
          rte_strerror(-retval));
      return retval;
    }
  }

  /* Stats bindings (if more than one queue) */
  if(dev_info.max_rx_queues > 1) {
    for (q = 0; q < rx_rings; q++) {
      retval = rte_eth_dev_set_rx_queue_stats_mapping (port, q, q);
      if (retval) {
        RTE_LOG(WARNING, DPDKCAP, "rte_eth_dev_set_rx_queue_stats_mapping(...):"\
            " %s\n", rte_strerror(-retval));
        RTE_LOG(WARNING, DPDKCAP, "The queues statistics mapping failed. The "\
           "displayed queue statistics are thus unreliable.\n");
      }
    }
  }

  /* Enable RX in promiscuous mode for the Ethernet device. */
  rte_eth_promiscuous_enable(port);

  /* Display the port MAC address. */
  struct rte_ether_addr addr;
  rte_eth_macaddr_get(port, &addr);
  RTE_LOG(INFO, DPDKCAP, "Port %u: MAC=%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
      ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ", RXdesc/queue=%d\n",
      (unsigned) port,
      addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
      addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5],
      num_rxdesc);

  return 0;
}


static int init(int argc, char* argv[]){

    int ret;
    int i, j; // 遍历用的游标

    // 初始化EAL
    ret = rte_eal_init(argc, argv); 
    if(ret < 0){
        rte_exit(EXIT_FAILURE, "EAL 初始化失败\n");
    }

    // 初始化 port
    // 只需要 RECV_NB_PORTS 个用于数据包旁路的接收
    int dev_count = rte_eth_dev_count_avail();   //  获取所有可用的端口数量
    if(dev_count < PACKET_RECEIVE_PORTS_NUM){
        rte_exit(EXIT_FAILURE, "[ERROR] 没有足够的port，需要%d个，实际拥有%d个，程序退出\n",
            PACKET_RECEIVE_PORTS_NUM, dev_count);
    }

    dev_count = PACKET_RECEIVE_PORTS_NUM;

    // 创建port列表
    port_id* portList = malloc(sizeof(port_id) * dev_count);
    memset(portList, -1, dev_count);
    int nb_ports = 0;
    for(i = 0; i < dev_count; i++) {
        portList[nb_ports++] = i;
    }
    
    RTE_LOG(INFO, DPDKCAP, "port : 需要%d个，实际拥有%d个\n",
            PACKET_RECEIVE_PORTS_NUM, nb_ports);
    RTE_LOG(INFO,DPDKCAP,"Using %u ports to listen on\n", nb_ports);

    // 初始化mbuf池
    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS_DEFAULT, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // 创建一个无锁队列用于对数据包进行暂存
    // TODO : 这个之后可以研究一下 socket_id 的问题，到底要怎么绑定比较好
    // 目前使用的方法是所有的核心共享同一个，但是可以尝试根据CPU的距离不同的核心绑定不同的
    struct rte_ring *packet_capture_ring = rte_ring_create(
        "Packet Ring", rte_align32pow2(NUM_MBUFS_DEFAULT), rte_socket_id(), 0);

    // 初始化所有的lcore
    // 数据接收模块需要PACKET_RECEIVE_LCORE_NUM个
    // 特征提取模块需要FEATURE_EXTRACTION_LCORE_NUM个
    // 攻击检测模块需要DDOS_DETECTION_LCORE_NUM个
    nb_lcores = rte_lcore_count() - 1;  // 除掉1个master lcore
    if(nb_lcores < PACKET_RECEIVE_LCORE_NUM + FEATURE_EXTRACTION_LCORE_NUM + DDOS_DETECTION_LCORE_NUM + 1){
        rte_exit(EXIT_FAILURE, "[ERROR] 没有足够的lcore， 需要%d个，实际拥有%d个，程序退出\n",
            PACKET_RECEIVE_LCORE_NUM + FEATURE_EXTRACTION_LCORE_NUM + DDOS_DETECTION_LCORE_NUM + 1, nb_lcores);
    }
    nb_lcores = PACKET_RECEIVE_LCORE_NUM + FEATURE_EXTRACTION_LCORE_NUM + DDOS_DETECTION_LCORE_NUM;
    lcore_list = malloc(nb_lcores * sizeof(lcore_id));
    memset(lcore_list, -1, nb_lcores);

    i = 0;
    uint8_t lcoreID = rte_get_next_lcore(-1, 1, 0); // 获取第一个 worker lcore

    // 创建数据接收模块所需要的lcore
    packet_capture_core_list = malloc(PACKET_RECEIVE_LCORE_NUM * sizeof(struct PacketCaptureCoreConfig*));
    memset(packet_capture_core_list, 0, PACKET_RECEIVE_LCORE_NUM);

    j = 0;
    port_id portID;

    for(j = 0; j < nb_ports; j++) {

        portID = portList[j];

        // 初始化并开启这个port
        printf("正在初始化 port %d ...\n", portID);
        ret = port_init(portID, 1, RX_DESC_DEFAULT, mbuf_pool);
        if (ret) {
            rte_exit(EXIT_FAILURE, "Cannot init port %d\n", portID);
        }

        // TODO 这里理论上有点小问题，目前暂时不考虑多队列的问题

        lcore_list[i++] = lcoreID;    // 记录 lcoreID

        // 创建数据包抓取节点
        packet_capture_core_list[j] = malloc(sizeof(struct PacketCaptureCoreConfig));
        packet_capture_core_list[j]->lcore = lcoreID;
        packet_capture_core_list[j]->port = portID;
        packet_capture_core_list[j]->queue = 0;
        packet_capture_core_list[j]->ring = packet_capture_ring;

        // 开启这个lcore
        ret = rte_eal_remote_launch((lcore_function_t *) PacketCapture, packet_capture_core_list[j], lcoreID); 
        if (ret) {
            rte_exit(EXIT_FAILURE, "[ERROR] lcore %d 创建失败，程序退出。\n", lcoreID);
        }
        
        lcoreID = rte_get_next_lcore(lcoreID, SKIP_MASTER, 0); // 获取第一个worker lcore

        // 开启端口
        ret = rte_eth_dev_start(portID);    
        if (ret) {
            rte_exit(EXIT_FAILURE, "[ERROR] port %d (j = %d)开启失败\n", portID, j);
        }
    }

    // 创建用于特征提取的 lcore
    feature_extract_core_list = malloc(FEATURE_EXTRACTION_LCORE_NUM * sizeof(struct FeatureExtractCoreConfig*));
    memset(feature_extract_core_list, 0, FEATURE_EXTRACTION_LCORE_NUM);

    char* HTTP_GET_feature_table_name;
    char* HTTP_POST_feature_table_name;

    for(j = 0; j < FEATURE_EXTRACTION_LCORE_NUM; j++){

        // 记录
        lcore_list[i++] = lcoreID;

        feature_extract_core_list[j] = malloc(sizeof(struct FeatureExtractCoreConfig));
        feature_extract_core_list[j]->lcore = lcoreID;
        feature_extract_core_list[j]->pktCnt = 0;
        feature_extract_core_list[j]->ring = packet_capture_ring;

        // 创建特征表
        feature_extract_core_list[j]->featureTableList = malloc(ATK_TYPE_TOTAL_NUM * sizeof(struct rte_hash*));

        // HTTP GET 特征表
        HTTP_GET_feature_table_name = malloc(64);
        snprintf(HTTP_GET_feature_table_name, 64, FEATURE_TABLE_NAME_FORMAT, lcoreID, "HTTPGET");
        feature_extract_core_list[j]->featureTableList[ATK_TYPE_HTTP_GET]
            = CreateFeatureTable(HTTP_GET_feature_table_name);

        // HTTP POST 特征表
        HTTP_POST_feature_table_name = malloc(64);
        snprintf(HTTP_POST_feature_table_name, 64, FEATURE_TABLE_NAME_FORMAT, lcoreID, "HTTPPOST");
        feature_extract_core_list[j]->featureTableList[ATK_TYPE_HTTP_POST]
            = CreateFeatureTable(HTTP_POST_feature_table_name);

        // 开启这个lcore
        ret = rte_eal_remote_launch((lcore_function_t *) FeatureExtract, feature_extract_core_list[j], lcoreID); 
        if (ret) {
            rte_exit(EXIT_FAILURE, "[ERROR] lcore %d 创建失败，程序退出。\n", lcoreID);
        }
        lcoreID = rte_get_next_lcore(lcoreID, SKIP_MASTER, 0); // 获取第一个worker lcore
    }

    // 创建用于攻击检测的core
    struct DDoSDetectCoreConfig** DDoS_detect_core_list
        = malloc(ATK_TYPE_TOTAL_NUM * sizeof(struct DDoSDectectCoreConfig*));
    j = 0;
    // 检测 HTTP GET
    lcore_list[i++] = lcoreID;
    DDoS_detect_core_list[j] = malloc(sizeof(struct DDoSDetectCoreConfig));

    DDoS_detect_core_list[j]->name = "HTTP GET FLOOD";
    DDoS_detect_core_list[j]->fileName_log = "./../log/HTTP_GET_FLOOD.log";
    DDoS_detect_core_list[j]->fileName_debug = "./../log/HTTP_GET_FLOOD.debug";
    DDoS_detect_core_list[j]->atkType = ATK_TYPE_HTTP_GET;
    DDoS_detect_core_list[j]->lcore = lcoreID;
    DDoS_detect_core_list[j]->featureTable = CreateFeatureTable("HTTP_GET_FEATURE_TABLE");
    DDoS_detect_core_list[j]->detectionWinSize = 1;

    ret = rte_eal_remote_launch((lcore_function_t *)DDoSDetect, DDoS_detect_core_list[j], lcoreID);
    if(ret) {
        rte_exit(EXIT_FAILURE, "[ERROR] 用于执行 HTTP GET 攻击检测的 lcore %d 创建失败，程序退出。\n", lcoreID);
    }

    j++;
    lcoreID = rte_get_next_lcore(lcoreID, SKIP_MASTER, 0);

    // 创建特征传递核心
    lcore_list[i++] = lcoreID;
    struct FeatureUpdateCoreConfig* featureUpdateCore
        = malloc(sizeof(struct FeatureUpdateCoreConfig));
    
    featureUpdateCore->lcore = lcoreID;
    featureUpdateCore->num_featureExtractCore = NUMS_FEATURE_EXTRACTION_CORE_DEFAULT;
    featureUpdateCore->featureExtractCoreList = feature_extract_core_list;
    featureUpdateCore->num_ddosDetectCore = NUMS_ATTACK_DETECTION_CORE_DEFAULT;
    featureUpdateCore->ddosDetectCoreList = DDoS_detect_core_list;
    featureUpdateCore->feature_update_win = 1;
    featureUpdateCore->pktNum_threshold = 1;

    ret = rte_eal_remote_launch((lcore_function_t *)FeatureUpdate, featureUpdateCore, lcoreID);
    if(ret) {
        rte_exit(EXIT_FAILURE, "[ERROR] 用于执行特征异步转换 lcore %d 创建失败，程序退出。\n", lcoreID);
    }
    return 0;
}


bool should_stop = false;
static void signal_handler(int sig) {

    RTE_LOG(NOTICE, DPDKCAP, "Caught signal %s on core %u%s\n",
        strsignal(sig), rte_lcore_id(),
        rte_get_master_lcore()==rte_lcore_id()?" (MASTER CORE)":"");

    int i;

    for(i = 0; i < PACKET_RECEIVE_LCORE_NUM; i++) {
        if(packet_capture_core_list[i] != NULL) {
            packet_capture_core_list[i]->isRunning = false;
        }
    }

    for(i = 0; i < FEATURE_EXTRACTION_LCORE_NUM; i++) {
        if(feature_extract_core_list[i] != NULL){
            feature_extract_core_list[i]->isRunning = false;
        }
    }

    sleep(10);

    should_stop = true;
}

int main(int argc, char* argv[]) {
    
    // 捕获 CTRL+C信号
    signal(SIGINT, signal_handler);

    init(argc, argv);
    
    while(!should_stop);

    // 退出
    RTE_LOG(NOTICE, DPDKCAP, "Waiting for all cores to exit\n");
    for (int i = 0; i < nb_lcores; i++) {
        int ret = rte_eal_wait_lcore(lcore_list[i]);
        if (ret < 0) {
            RTE_LOG(ERR, DPDKCAP, "Core %d did not stop correctly.\n", lcore_list[i]);
        }
    }
    return 0;
}