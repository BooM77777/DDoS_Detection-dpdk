#include "featureExtractCore.h"
#include "feature.h"

// 将特征更新到对应的哈希表中
void update_feature(struct rte_hash* feature_table, uint32_t src_ip, uint16_t payload_len){

	// 创建键
	struct Key* k = malloc(sizeof(struct Key));
	k->aimIP = src_ip;

	// 创建值
	struct Feature* f;

	int ret = rte_hash_lookup_data(feature_table, k, &f);
	if(ret == -ENOENT){
		// 没有查询到值，创建新的特征并加入哈希表中
		f = createFeature(payload_len);
		rte_hash_add_key_data(feature_table, k, f);
	}else{
		// 如果查询到了数值，对查询到指针的对应值进行修改
		combineFeatureWithLength(f, payload_len);
		// 清空之前创建的key
		free(k);
	}
}

// HTTP报文的处理
int process_http_pkt(
	struct FeatureExtractCoreConfig* config, uint32_t src_ip, uint16_t http_payload_len,uint8_t* http_payload){

	uint8_t atk_type = -1;
	// 首先检测是否为 slow header 攻击，通过是否包含连续的两个 \r\n 来进行判断
	char* find = strstr(http_payload, "\r\n\r\n");
	if(find == NULL){
		// 如果没有包含结束符
		atk_type = ATK_TYPE_HTTP_POST;
	}else{
		// 如果全是正常的HTTP报文，则判断请求方法
		switch (http_payload[0]){
		// 简单的判断第一个字符
		case 'G':
			atk_type = ATK_TYPE_HTTP_GET;
			break;
		case 'P':
			atk_type = ATK_TYPE_HTTP_POST;
			break;
		default:
			// 如果均不满足则说明是坏包但是，目前均不做处理
			break;
		}
	}

	// 匹配到了关注的报文类型
	if(atk_type != -1){
		update_feature(config->featureTableList[atk_type], src_ip, http_payload_len);
	}
	return 0;
}

int feature_extract_process(struct FeatureExtractCoreConfig* config, struct rte_mbuf** bufs, int pktCnt){

	struct rte_mbuf* pkt;

	struct rte_ether_hdr* ether_hdr = NULL;
	struct rte_ipv4_hdr* ipv4_hdr = NULL;
	struct rte_tcp_hdr* tcp_hdr = NULL;
	struct rte_udp_hdr* udp_hdr = NULL;

	uint32_t srcIP = -1, dstIP = -1;
	uint16_t srcPort = -1, dstPort = -1;
	uint8_t* application_layer_payload;
	uint16_t payload_len;
	int offset;

	for (int i = 0; i < pktCnt; i++) {

		// 重制计数器
		offset = 0;
		srcIP = -1, dstIP = -1;
		srcPort = -1, dstPort = -1;

		pkt = bufs[i];	// 获取到需要被处理的报文

		// 获取以太帧
		ether_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
		offset += sizeof(struct rte_ether_hdr);

		if (ether_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
			// 处理IPv4报文
			ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr*, offset);
			offset += sizeof(struct rte_ipv4_hdr);

			srcIP = rte_be_to_cpu_32(ipv4_hdr->src_addr);	// 记录源地址
			dstIP = rte_be_to_cpu_32(ipv4_hdr->dst_addr);	// 记录目的地址

			switch (ipv4_hdr->next_proto_id)
			{
			case IPPROTO_TCP:
				// 提取TCP报文头部
				tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr*, offset);
				offset += tcp_hdr->data_off / 4;

				srcPort = rte_cpu_to_be_16(tcp_hdr->src_port);	// 记录源端口
				dstPort = rte_cpu_to_be_16(tcp_hdr->dst_port);	// 记录源端口

				payload_len
					= rte_be_to_cpu_16(ipv4_hdr->total_length) - sizeof(struct rte_ipv4_hdr) - tcp_hdr->data_off / 4;
				application_layer_payload = rte_pktmbuf_mtod_offset(pkt, uint8_t*, offset);
				
				// TODO : 添加用户自定义的端口配置，配置发送往哪些服务的那些端口需要被重点防护
				switch (dstPort){
				// 考虑对一般HTTP服务的防护
				case 80:
					display(srcIP, srcPort, dstIP, dstPort, "HTTP");
					process_http_pkt(config, srcIP, payload_len, application_layer_payload);
					break;
				case 443:
					// display(srcIP, srcPort, dstIP, dstPort, "SSL/TLS");
					break;
				default:
					break;
				}

				// printf("%u:%u == TCP ==> %u:%u\n", srcIP, srcPort, dstIP, dstPort);
				
			case IPPROTO_UDP:
				// 提取UDP报文头部
				udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr*, offset);
				offset += udp_hdr->dgram_len * 4;

				srcPort = rte_cpu_to_be_16(udp_hdr->src_port);	// 记录源端口
				dstPort = rte_cpu_to_be_16(udp_hdr->dst_port);	// 记录源端口

				if(srcPort == 53 || dstPort == 53){

					// display(srcIP, srcPort, dstIP, dstPort, "DNS");
				}
				break;
			default:
				// printf("其他协议，协议号：%u\n", ipv4_hdr->next_proto_id);
				break;
			}
		}
	}
}

int FeatureExtract(struct FeatureExtractCoreConfig* config) {

	uint16_t nb_pkt;
    uint16_t nb_rx_enqueued;
    struct rte_mbuf *buffer[DPDKCAP_CAPTURE_BURST_SIZE];

	config->isRunning = true;

	RTE_LOG(INFO, DPDKCAP, "lcore %u 用于特征提取\n", config->lcore);

	for(;;){
		
		if(unlikely(!config->isRunning)){
			break;
		}
		// 从无锁队列中读取数据包
		nb_pkt = rte_ring_dequeue_burst(config->ring, (void*)buffer, 8192, NULL);
		// printf("%d\n", nb_pkt);
		// 处理数据包
		if(likely(nb_pkt > 0)){
			feature_extract_process(config, buffer, nb_pkt);
		}
    }

	return 0;
}