/* HS-only ECM resource ordering from pinned SDM845 gadget.c:
 * DEPSTARTCFG(0), one resource for each used hardware endpoint, then
 * SETEPCONFIG. Resources survive USB bus resets, not controller resets.
 */
#ifndef POLARIS_DWC3_ENDPOINTS_H
#define POLARIS_DWC3_ENDPOINTS_H
#include <stdint.h>
typedef int (*pdwc3_ep_command)(void *, unsigned, uint32_t, uint32_t, uint32_t, uint32_t);
static inline int polaris_dwc3_ep0(pdwc3_ep_command command, void *ctx)
{
    if (!command) return -1;
    if (command(ctx, 0, 9, 0, 0, 0)) return -1;
    /* Hardware endpoints0..5 cover EP0 plus ECM bulk and interrupt IN. */
    for (unsigned ep = 0; ep < 6; ep++)
        if (command(ctx, ep, 2, 1, 0, 0)) return -1;
    for (unsigned ep = 0; ep < 2; ep++)
        if (command(ctx, ep, 1, 64u << 3, (1u << 8) | (1u << 10) | (ep << 25), 0)) return -1;
    return 0;
}
static inline int polaris_dwc3_ecm(pdwc3_ep_command command, void *ctx)
{
    if (!command) return -1;
    /* Do not reset/reallocate transfer resources on SET_CONFIGURATION. */
    if (command(ctx, 2, 1, (2u << 1) | (512u << 3), (1u << 8) | (2u << 25), 0) ||
        command(ctx, 3, 1, (2u << 1) | (512u << 3) | (1u << 17), (1u << 8) | (3u << 25), 0) ||
        command(ctx, 5, 1, (3u << 1) | (16u << 3) | (2u << 17),
            (1u << 8) | (8u << 16) | (5u << 25), 0)) return -1;
    return 0;
}
#endif
