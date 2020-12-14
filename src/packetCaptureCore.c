#include "packetCaptureCore.h"
#include "feature.h"
#include "string.h"
#include "rte_hash.h"

int PacketCapture(struct PacketCaptureCoreConfig* config) {

	uint16_t nb_rx;
    uint16_t nb_rx_enqueued;
    struct rte_mbuf *buffer[DPDKCAP_CAPTURE_BURST_SIZE];

	config->isRunning = true;

	RTE_LOG(INFO, DPDKCAP, "lcore %u 从 port %u 中抓取数据包\n", config->lcore, config->port);

	for(;;){

		if(unlikely(!config->isRunning)){
			break;
		}

		// 这个应该不需要了
		// sleep(1);

		// 从RX队列中读取数据包
		nb_rx = rte_eth_rx_burst(config->port, config->queue, buffer, DPDKCAP_CAPTURE_BURST_SIZE);
		// printf("hello %d\n", nb_rx);
		// 将读取到的数据包扔到无锁队列中
		if(likely(nb_rx > 0)){
			nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void*)buffer, nb_rx, NULL);
		}
	}
	// 退出
	// 清空缓冲区
	free(buffer);
	RTE_LOG(INFO, DPDKCAP, "用于抓取数据包的 lcore %u 成功关闭\n", config->lcore);

	return 0;
}