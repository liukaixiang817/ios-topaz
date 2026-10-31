/* Native call entry for the same bounded read-only physical SMEM witness. */
#include "polaris-wifi-smem-probe.h"
#ifdef POLARIS_WIFI_GLINK_HOST_TEST
#include <errno.h>
#else
#include <sys/errno.h>
#endif
int
polaris_wifi_smem_readonly_probe(const struct polaris_wifi_probe_io *io, uint32_t remote,
    struct polaris_wifi_probe_result *out, struct polaris_wifi_probe_workspace *work)
{
    if (!io || !out || !work) return EINVAL;
    return polaris_wifi_smem_probe(io, remote, out, work) ? 0 : EIO;
}
