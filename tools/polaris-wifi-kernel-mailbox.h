/* XNU-facing resident Wi-Fi transport. The station/ifnet adapter must poll
 * responses/events, and only report link up after the native LINK event. */
#ifndef POLARIS_WIFI_KERNEL_MAILBOX_H
#define POLARIS_WIFI_KERNEL_MAILBOX_H
#include "polaris-wifi-mailbox.h"
extern uint8_t polaris_wifi_mailbox_page[PWMB_BYTES];
int polaris_wifi_mailbox_attach(struct pwmb_identity*);
int polaris_wifi_mailbox_request(unsigned,const uint8_t*,unsigned,uint64_t*);
int polaris_wifi_mailbox_transmit(const uint8_t*,unsigned);
/* poll returns1 for a private message,0 for idle,-errno on failure. */
int polaris_wifi_mailbox_poll(unsigned,struct pwmb_message*);
unsigned polaris_wifi_mailbox_status(void); /* bit0 radio ready,bit1 link,bit2 fault,bit3 sealed,bit4 unavailable */
int polaris_wifi_mailbox_seal(void); /* closes new work immediately; retry EBUSY until private wipe completes */
#endif
