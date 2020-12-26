#include "stdint.h"
#include "common.h"

struct Container {
    /* data */
    float* data;
    uint32_t tail;
    uint32_t cap;

    float upperBound, lowerBound;
};

struct Container* createContainer(int size);

void addDataToContainer(struct Container* q, float data);

void getBound(struct Container* q, uint8_t type);