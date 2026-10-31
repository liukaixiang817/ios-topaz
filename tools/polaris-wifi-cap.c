/* Original Polaris client using own MiCode CAP wire definition. */
#include "polaris-wifi-cap.h"
#ifdef POLARIS_WIFI_GLINK_HOST_TEST
#include <errno.h>
#include <string.h>
#else
#include <sys/errno.h>
#include <libkern/libkern.h>
#endif

static void
cap_server(void *ctx, bool arrived, uint32_t service, uint32_t version,
    uint32_t instance, uint32_t node, uint32_t port)
{
    struct polaris_wifi_cap_client *c = ctx;
    if (service != PW_SERVICE || version != PW_VERSION || instance != PW_INSTANCE || c->error) return;
    if (!port || node >= 0xfffffffeu || port >= 0xfffffffeu) { c->error = EPROTO; return; }
    if (!arrived) {
        if (c->discovered && c->node == node && c->service_port == port) c->error = ENOTCONN;
        return;
    }
    if (c->discovered && (c->node != node || c->service_port != port)) {
        c->error = EADDRINUSE; return; /* Never choose an arbitrary WLFW service. */
    }
    c->node = node; c->service_port = port; c->discovered = true;
}

static void
cap_receive(void *ctx, uint32_t node, uint32_t port, const void *bytes, size_t n)
{
    struct polaris_wifi_cap_client *c = ctx;
    if (!c->discovered || node != c->node || port != c->service_port) { c->unrelated++; return; }
    if (c->error) return;
    if (!c->awaiting || n > sizeof(c->raw)) { c->error = EPROTO; return; }
    memcpy(c->raw, bytes, n); c->raw_bytes = n; /* Preserve actual received bytes. */
    if (!polaris_wlfw_cap_response(PW_SERVICE, PW_VERSION, PW_INSTANCE, c->transaction,
        c->raw, n, &c->capability)) { c->error = EPROTO; return; }
    c->awaiting = false;
    if (!polaris_wlfw_cap_has_identity(&c->capability)) { c->error = ENODEV; return; }
    c->done = true; /* Identity response only; no radio/DMA/scan/join conclusion. */
}

static int
cap_scope(struct polaris_wifi_cap_client *c)
{
    struct polaris_wifi_glink_status s;
    int error;
    if (!c || !c->transport || !c->port) return EINVAL;
    if (c->error) return (int)c->error;
    error = polaris_wifi_glink_status(c->transport, &s);
    if (error) return error;
    if (s.epoch != c->epoch || s.first_error || s.uncertain || !s.up || s.stopping) {
        c->error = EIO; return EIO;
    }
    return 0;
}

int
polaris_wifi_cap_open(struct polaris_wifi_cap_client *c, struct polaris_wifi_glink *g, uint64_t now)
{
    struct polaris_wifi_glink_status s;
    if (!c || !g) return EINVAL;
    int error = polaris_wifi_glink_status(g, &s);
    if (error) return error;
    if (!s.up || s.stopping || s.first_error || s.uncertain) return ENOTCONN;
    memset(c, 0, sizeof(*c)); c->transport = g; c->epoch = s.epoch; c->last_us = now;
    c->ops = polaris_wifi_glink_qrtr_ops(g);
    if (!c->ops || !(c->port = c->ops->open(cap_receive, cap_server, c))) return EBUSY;
    error = c->ops->lookup(c->port, PW_SERVICE, PW_VERSION, PW_INSTANCE);
    if (error) { c->error = (uint32_t)error; return error; }
    return 0;
}

int
polaris_wifi_cap_request(struct polaris_wifi_cap_client *c, uint16_t transaction, uint64_t now)
{
    uint8_t request[7];
    int error = cap_scope(c);
    if (error) return error;
    if (!transaction || now < c->last_us) { c->error = EINVAL; return EINVAL; }
    c->last_us = now;
    if (!c->discovered) return EAGAIN;
    if (c->requested) return EALREADY;
    if (!polaris_wlfw_cap_request(transaction, request, sizeof(request))) return EINVAL;
    c->requested = c->awaiting = true; c->transaction = transaction; c->issued_us = now;
    error = c->ops->send(c->port, c->node, c->service_port, request, sizeof(request));
    if (error) { c->error = (uint32_t)error; return error; }
    return c->error ? (int)c->error : 0;
}

int
polaris_wifi_cap_poll(struct polaris_wifi_cap_client *c, uint64_t now)
{
    int error = cap_scope(c);
    if (error) return error;
    if (now < c->last_us) { c->error = EINVAL; return EINVAL; }
    c->last_us = now;
    error = polaris_wifi_glink_poll_once(c->transport);
    if (error) { c->error = (uint32_t)error; return error; }
    if (c->awaiting && now - c->issued_us >= 5000000u) { c->error = ETIMEDOUT; return ETIMEDOUT; }
    return c->error ? (int)c->error : c->done ? 0 : EAGAIN;
}

int
polaris_wifi_cap_close(struct polaris_wifi_cap_client *c)
{
    if (!c || !c->port) return EINVAL;
    if (c->awaiting) return EBUSY; /* No silent abandon of an issued request. */
    int error = polaris_wifi_glink_close_port(c->port);
    if (!error) c->port = NULL;
    return error;
}
