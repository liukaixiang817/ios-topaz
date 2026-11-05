/* SPDX-License-Identifier: ISC
 * Copyright (c) 2018 The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * WCN3990 SNOC data from Linux stable458c6079fc1d41d564c37679c8ace02cd83ee817
 * drivers/net/wireless/ath/ath10k/{snoc.c,ce.h,htc.h}. Converted to the own
 * Polaris c7cb50c1 QMI wire types. These are host/target protocol plans, not
 * inherited physical addresses, allocated DMA buffers or power authority.
 * Own DT: ICNSS18800000/8MiB,12 CE IRQs,1MiB MSA,SMMU stage1 bypass.
 */
#ifndef POLARIS_WIFI_WCN3990_CONFIG_H
#define POLARIS_WIFI_WCN3990_CONFIG_H
#include "polaris-wifi-wlfw.h"
static const struct pwfw_ce_config polaris_wcn3990_config={
    .targets=12,.services=21,.shadows=12,
    .target={
        {0,2,32,2048,0},{1,1,32,2048,0},{2,1,64,2048,0},{3,2,32,2048,0},
        {4,2,256,256,8},{5,2,1024,64,8},{6,3,32,16384,0},{7,4,0,0,8},
        {8,1,32,2048,0},{9,1,32,2048,0},{10,1,32,2048,0},{11,1,32,2048,0},
    },
    .service={
        {0x104,2,3},{0x104,1,2},{0x102,2,3},{0x102,1,2},
        {0x101,2,3},{0x101,1,2},{0x103,2,3},{0x103,1,2},
        {0x100,2,3},{0x100,1,2},{0x001,2,0},{0x001,1,2},
        {0xfe00,2,0},{0xfe00,1,2},{0x300,2,4},{0x300,1,1},
        {0xfe00,2,5},{0x301,1,9},{0x302,1,10},{0x600,1,11},{0,0,0},
    },
    .shadow={
        {0,0x3c},{3,0x3c},{4,0x3c},{5,0x3c},{7,0x3c},{1,0x40},
        {2,0x40},{7,0x40},{8,0x40},{9,0x40},{10,0x40},{11,0x40},
    },
};
struct pwcn_host_pipe {uint16_t source_entries,destination_entries,bytes;uint16_t flags;};
static const struct pwcn_host_pipe polaris_wcn3990_host[12]={
    {16,0,2048,0},{0,512,2048,0},{0,64,2048,0},{32,0,2048,0},
    {2048,0,256,8},{0,512,512,0},{0,0,0,0},{2,2,2048,0},
    {0,128,2048,0},{0,512,2048,0},{0,512,2048,0},{0,512,2048,0},
};
#endif
