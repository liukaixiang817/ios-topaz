/* Fixed private bring-up ioctl, transported by SIOC{G,S}DRVSPEC64 on en0.
 * Only a privileged local process may use it. No kernel/firmware address is
 * accepted in this wire record. Apple80211/wifid integration is separate. */
#ifndef POLARIS_WIFI_INTERFACE_H
#define POLARIS_WIFI_INTERFACE_H
#include "polaris-wifi-mailbox.h"
#define PWIF_COMMAND UINT64_C(0x5057494643544c31)
#define PWIF_VERSION 1u
#define PWIF_BYTES 1600u
void polaris_wifi_interface_start(void);
int polaris_wifi_interface_seal(void);
/* SET: version32@0, operation32@4, bytes32@8, zero32@12, then payload@64.
 * bytes16..63 and all unused payload bytes must be zero.
 * GET: version32, current flags32, last errno32, response bytes32, local
 * request id64@16, completion id64@24, sent packets64@32, received64@40,
 * TX drops64@48, RX drops64@56; last reply data at64. Never returns JOIN
 * input or passphrase. GET has no destructive read/cancel semantics.
 * Flags: bit0 radio,1 link,2 fault,3 sealed,4 request pending,5 ifnet attached.
 * One control operation at a time. Accepted SET returns immediately; GET
 * completion id catches up to request id only after a matching radio reply.
 */
static inline int pwif_request_valid(const uint8_t*p)
{
    if(!p||pwmb_u32(p)!=PWIF_VERSION||pwmb_u32(p+12)||!pwmb_zero(p+16,48))return 0;
    unsigned op=pwmb_u32(p+4),bytes=pwmb_u32(p+8);
    return pwmb_payload(PWMB_CONTROL,op,p+64,bytes)&&pwmb_zero(p+64+bytes,PWMB_DATA-bytes);
}
#endif
