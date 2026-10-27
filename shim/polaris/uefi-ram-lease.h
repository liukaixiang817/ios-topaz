/* RAM trials have no writable root on UFS. If the host vanishes for30min,
 * return to FASTBOOT instead of leaving an uncontrolled kernel running.
 * This policy must not be reused for a writable persistent OS without a
 * kernel shutdown/flush handshake. It is not a kernel panic interceptor. */
#ifndef POLARIS_UEFI_RAM_LEASE_H
#define POLARIS_UEFI_RAM_LEASE_H
#include <stdint.h>
#define POLARIS_RAM_LEASE_SECONDS 1800u
struct polaris_efi_ram_lease {uint64_t last;unsigned active,fired;};
static inline void polaris_efi_ram_lease_activity(struct polaris_efi_ram_lease *lease,uint64_t now)
{if(lease->active){lease->last=now;lease->fired=0;}}
static inline int polaris_efi_ram_lease_expired(struct polaris_efi_ram_lease *lease,uint64_t now,uint64_t frequency)
{
    if(!lease->active||lease->fired||!frequency||frequency>UINT64_MAX/POLARIS_RAM_LEASE_SECONDS)return 0;
    if(now-lease->last<frequency*POLARIS_RAM_LEASE_SECONDS)return 0;
    lease->fired=1;return 1;
}
#endif
