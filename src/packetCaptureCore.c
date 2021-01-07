#include "packetCaptureCore.h"
#include "feature.h"
#include "string.h"
#include "rte_hash.h"

int PacketCapture(struct PacketCaptureCoreConfig* config) {

	int i;

	int pktEenqueuedCnt = 0;
	int pktCnt = 0;
	int pktMissing = 0;

	uint16_t nb_rx;
    int nb_rx_enqueued;
    struct rte_mbuf *buffer[DPDKCAP_CAPTURE_BURST_SIZE];

	config->isRunning = true;

	RTE_LOG(INFO, DPDKCAP, "lcore %u 从 port %u 中抓取数据包\n", config->lcore, config->port);

	printf("port = %d | queue = %d\n", config->port, config->queue);

    clock_t start,end; // 用来计时
    start = clock();

	for(;;){
		// 停止条件判断
		if(unlikely(!config->isRunning)){
			break;
		}
		// 从RX队列中读取数据包
		nb_rx = rte_eth_rx_burst(config->port, config->queue, buffer, DPDKCAP_CAPTURE_BURST_SIZE);

		// 将读取到的数据包扔到无锁队列中
		if(likely(nb_rx > 0)){
			nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void*)buffer, nb_rx, NULL);


			for (i = 0; i < nb_rx; i++) {
				rte_pktmbuf_free(buffer[i]);
			}

			if (nb_rx != nb_rx_enqueued) {
				pktMissing = nb_rx - nb_rx_enqueued;
				for (i = nb_rx_enqueued; i < nb_rx; i++) {
					rte_pktmbuf_free(buffer[i]);
				}
			}

			// printf("+%d\n", nb_rx);
			pktCnt += nb_rx;
			pktEenqueuedCnt += nb_rx_enqueued;
			
			// end = clock();
			// if((double)(end-start)/CLOCKS_PER_SEC >=2) {
			// 	printf("抓到了%d个数据包。一共处理了%d个，丢包%d\n", pktCnt, pktEenqueuedCnt, pktMissing);
			// 	pktCnt = 0;
			// 	pktEenqueuedCnt = 0;
			// 	pktMissing = 0;
			// 	start = end;
			// }
		}
	}
	// 退出
	// 清空缓冲区
	free(buffer);
	RTE_LOG(INFO, DPDKCAP, "一共抓取到 %d 个数据包\n", pktCnt);
	RTE_LOG(INFO, DPDKCAP, "用于抓取数据包的 lcore %u 成功关闭\n", config->lcore);

	return 0;
}
