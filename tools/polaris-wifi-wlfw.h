/* Own Polaris ICNSS startup over the existing admitted GLINK/QRTR worker.
 * Caller retains power, current MSA backing and actual assignment ownership.
 * FW_READY is a firmware indication, never scan/join/data readiness. */
#ifndef POLARIS_WIFI_WLFW_H
#define POLARIS_WIFI_WLFW_H
#include "polaris-wifi-cap.h"
struct pwfw_region {uint64_t address;uint32_t bytes;uint8_t secure,reserved[3];};
struct pwfw_ce_target {uint32_t pipe,direction,entries,bytes,flags;};
struct pwfw_ce_service {uint32_t service,direction,pipe;};
struct pwfw_ce_shadow {uint16_t pipe,offset;};
struct pwfw_ce_config {
    uint32_t targets,services,shadows;
    struct pwfw_ce_target target[12];struct pwfw_ce_service service[24];struct pwfw_ce_shadow shadow[24];
};
struct polaris_wifi_wlfw_cfg {
    struct polaris_wifi_glink*transport;uint64_t msa;uint32_t bytes;
    bool (*scope)(void*); /* Current native power/RMTFS/backing/CPU lifetime. */
    bool (*assign)(void*,const struct pwfw_region*,unsigned); /* Actual exact-region MP_ASSIGN; false retains UNKNOWN. */
    void*ctx;
};
struct pwfw_exchange {
    uint64_t issued;uint16_t transaction,message;uint32_t request_bytes,response_bytes;
    bool requested,received,accepted;uint8_t request[648],response[210];
};
struct polaris_wifi_wlfw {
    struct polaris_wifi_wlfw_cfg cfg;const struct polaris_wifi_qrtr_ops*ops;struct polaris_wifi_qrtr_port*port;
    uint64_t epoch,opening,last_us,fw_status;
    uint32_t node,service_port,error,unrelated,phase,regions,fw_indications,msa_indications,pin_valid,pin[3];
    bool discovered,busy,assign_issued,assigned,fw_ready,ready;
    bool enable_requested,enabled,disable_requested,disabled;
    struct pwfw_region region[2];struct pwfw_exchange exchange[7];struct polaris_wlfw_cap capability;
    struct pwfw_ce_config ce;
};
/* Zero, caller-owned storage. No restart, reinitialization or implicit free. */
int polaris_wifi_wlfw_open(struct polaris_wifi_wlfw*,const struct polaris_wifi_wlfw_cfg*,uint64_t);
/* Sole native worker; nested public calls fail. Call RMTFS poll on the same
 * worker between these steps. Receive callbacks only retain wire evidence. */
int polaris_wifi_wlfw_poll(struct polaris_wifi_wlfw*,uint64_t);
/* Copies a bounded host CE plan, then poll sends CFG23 followed by MISSION22.
 * The native caller must own its DMA/rings before requesting activation.
 * OFF acknowledgment is firmware control evidence, not CE/DMA retirement. */
int polaris_wifi_wlfw_enable(struct polaris_wifi_wlfw*,const struct pwfw_ce_config*);
int polaris_wifi_wlfw_disable(struct polaris_wifi_wlfw*);
#endif
