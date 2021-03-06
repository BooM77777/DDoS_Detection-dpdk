#ifndef UTIL_H
#define UTIL_H

#include "stdint.h"

float mean(float* data, uint32_t len);   // 计算序列均值
float stdDev(float* data, uint32_t len);    // 计算序列标准差

float entropy(const uint32_t* list, uint32_t size);  // 计算序列熵值

void display(uint32_t, uint16_t, uint32_t, uint16_t, const char*);

#endif