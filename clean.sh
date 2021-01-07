#!/bin/sh

clear

export RTE_SDK=/usr/local/dpdk/dpdk-stable-19.11.6
export RTE_TARGET=x86_64-native-linuxapp-gcc

make clean

rm -rf ./build
rm -rf ./log