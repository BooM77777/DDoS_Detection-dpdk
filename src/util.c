#include "util.h"
#include "stdio.h"
#include "math.h"

uint8_t* convertIPFromUint32(uint32_t ip) {
	uint8_t* ips = malloc(4 * sizeof(uint8_t));
	ips[3] = ip & 0xff;
	ips[2] = (ip >> 8) & 0xff;
	ips[1] = (ip >> 16) & 0xff;
	ips[0] = (ip >> 24) & 0xff;
	return ips;
}


void display(uint32_t srcIP, uint16_t srcPort, uint32_t dstIP, uint16_t dstPort, const char* proto) {
	uint8_t* srcIP_display = convertIP(srcIP);
	uint8_t* dstIP_display = convertIP(dstIP);
	printf("%u.%u.%u.%u : %u", srcIP_display[0], srcIP_display[1], srcIP_display[2], srcIP_display[3], srcPort);
	printf(" =*- %s -*=> ", proto);
	printf("%u.%u.%u.%u : %u\n", dstIP_display[0], dstIP_display[1], dstIP_display[2], dstIP_display[3], dstPort);
	free(srcIP_display);
	free(dstIP_display);
}


float mean(float* data, uint32_t len){
    if(len <= 0){
        return -1;
    }else{
        float avg = 0;
        for(int i = 0; i < len; i++){
            avg += data[i];
        }
        return avg / len;
    }
}

float stdDev(float* data, uint32_t len){
    if(len <= 0){
        return -1;
    }else{
        float res = 0;
        float avg = mean(data, len);
        for(int i = 0; i < len; i++){
            res += powf(data[i] - avg, 2);
        }
        res /= len;
        return powf(res, 0.5f);
    }
}

float entropy(const uint32_t* list, uint32_t size){
	int sum = 0;
	for (int i = 0; i < size; i++) {
		sum += list[i];
	}
	double res = 0;
	for (int i = 0; i < size; i++) {
		float p = (float)list[i] / sum;
		if (p > 0) {
			res -= p * log2(p);
		}
	}
	return (double)res;
}

float* meanFilter(float* historicalData, int historicalDataLen, uint8_t kernalSize){

    float* res = malloc((historicalDataLen - kernalSize + 1) * sizeof(float));

    for(int i = 0; i < historicalDataLen - kernalSize + 1; i++){
        res[i] = 0;
        for(int j = 0; j < kernalSize; j++){
            res[i] += historicalData[i+j];
        }
        res[i] /= kernalSize;
    }
    return res;
}
