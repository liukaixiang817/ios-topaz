/* Live service-discovered WLFW CAP client, not firmware activation or Wi-Fi. */
#ifndef POLARIS_WIFI_CAP_H
#define POLARIS_WIFI_CAP_H
#include "polaris-wifi-glink.h"
#include "polaris-wlfw.h"
struct polaris_wifi_cap_client {
    struct polaris_wifi_glink *transport;
    const struct polaris_wifi_qrtr_ops *ops;
    struct polaris_wifi_qrtr_port *port;
    uint64_t epoch, last_us, issued_us;
    uint32_t node, service_port, error, unrelated;
    uint16_t transaction;
    bool discovered, requested, awaiting, done;
    size_t raw_bytes;
    uint8_t raw[7 + PW_CAP_MAX_BODY];
    struct polaris_wlfw_cap capability;
};
/* A single native worker owns client API calls; transport callbacks may run
 * reentrantly on that worker. Caller owns object until callbacks have ended
 * and close succeeds. Concurrent use must be serialized by that owner. */
int polaris_wifi_cap_open(struct polaris_wifi_cap_client *, struct polaris_wifi_glink *, uint64_t);
/* One request total per object; no timeout/rejected-peer retry. Peer comes only
 * from live NEW_SERVER service0x45/version1/instance0. Does not guess node4/13. */
int polaris_wifi_cap_request(struct polaris_wifi_cap_client *, uint16_t, uint64_t);
int polaris_wifi_cap_poll(struct polaris_wifi_cap_client *, uint64_t);
int polaris_wifi_cap_close(struct polaris_wifi_cap_client *);
#endif
