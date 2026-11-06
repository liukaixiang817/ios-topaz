/* Physical bring-up stays in place when the host is idle. A finite lease
 * remains available for explicitly selected software lifecycle tests only.
 * Operation deadlines and explicit shutdown handshakes remain independent. */
#ifndef POLARIS_UEFI_RAM_LEASE_H
#define POLARIS_UEFI_RAM_LEASE_H
#include <stdint.h>
#ifndef POLARIS_RAM_LEASE_SECONDS
#define POLARIS_RAM_LEASE_SECONDS 0u
#endif
struct polaris_efi_ram_lease {uint64_t last;unsigned active,fired;};
static inline void polaris_efi_ram_lease_activity(struct polaris_efi_ram_lease *lease,uint64_t now)
{if(lease->active){lease->last=now;lease->fired=0;}}
static inline int polaris_efi_ram_lease_expired(struct polaris_efi_ram_lease *lease,uint64_t now,uint64_t frequency)
{
#if POLARIS_RAM_LEASE_SECONDS == 0
    (void)lease;(void)now;(void)frequency;return 0;
#else
    if(!lease->active||lease->fired||!frequency||frequency>UINT64_MAX/POLARIS_RAM_LEASE_SECONDS)return 0;
    if(now-lease->last<frequency*POLARIS_RAM_LEASE_SECONDS)return 0;
    lease->fired=1;return 1;
#endif
}
#endif
