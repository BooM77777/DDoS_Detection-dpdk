#include "container.h"
#include "stdlib.h"
#include "util.h"

#define FILTER_KERNEL 3

struct Container* createContainer(int cap) {

    struct Container* ret = malloc(sizeof(struct Container));
    ret->data = malloc(cap);
    memset(ret->data, 0, cap);
    ret->cap = cap;

    return ret;
}

void addDataToContainer(struct Container* c, float data) {

    c->data[c->tail++] = data;
    c->tail = c->tail % c->cap;
}

void getBound(struct Container* c, uint8_t type) {

        // 获取平滑后的
    float* smoothRes = meanFilter(c->data, c->cap, FILTER_KERNEL);

    float smoothRes_mean, smoothRes_std;
    float max_increase_delta, max_decrease_delta;

    switch (type){
    case BOUND_TYPE_MEAN:   // 使用3σ准则计算

        smoothRes_mean = mean(smoothRes, c->cap - FILTER_KERNEL + 1);     // 求均值
        smoothRes_std = stdDev(smoothRes, c->cap - FILTER_KERNEL + 1);    // 求方差
        c->upperBound = smoothRes_mean + 3 * smoothRes_std;   // 区间上界
        c->lowerBound = smoothRes_mean - 3 * smoothRes_std;   // 区间下界
        break;

    case BOUND_TYPE_MAX:    // 使用区间最大值计算

        c->upperBound = c->data[0];    // 初始化区间最大值
        c->lowerBound = c->data[0];    // 初始化区间最小值

        max_increase_delta = c->data[1] - c->data[0];   // 初始化最大增幅
        max_decrease_delta = c->data[1] - c->data[0];   // 初始化最大减幅

        for(int i = 1; i < c->cap; i++){
            // 计算最大值
            c->upperBound = max(c->upperBound, c->data[i]);
            // 计算最小值
            c->lowerBound = min(c->lowerBound, c->data[i]);
            // 计算最大幅度
            max_increase_delta = max(max_increase_delta, c->data[i] - c->data[i-1]);
            max_decrease_delta = min(max_decrease_delta, c->data[i] - c->data[i-1]);
        }

        c->upperBound += max(max_increase_delta, 0);
        c->lowerBound += min(max_decrease_delta, 0);

        break;
    
    default:
        break;
    }

    free(smoothRes);
}