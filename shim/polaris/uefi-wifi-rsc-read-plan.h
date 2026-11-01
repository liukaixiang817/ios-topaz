/* Default-OFF typed READ evidence to ARC plan. No hardware authority is
 * supplied by this pure function. The physical parent separately requires
 * current known-client/source/RAM/Device/CPU admission and checked I/O. */
#ifndef POLARIS_UEFI_WIFI_RSC_READ_PLAN_H
#define POLARIS_UEFI_WIFI_RSC_READ_PLAN_H
#ifndef EFI_XNU_WIFI_ARC_READ_AVAILABLE
#define EFI_XNU_WIFI_ARC_READ_AVAILABLE 0
#endif
#ifndef EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY
#define EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY 1
#endif
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-wifi-rsc-baseline.h"
#include "../../tools/polaris-wifi-rsc-read.h"
static inline int pwrr_plan(const struct pwrpb_baseline *b,const struct pwcd_resource d[3],
    const struct pwrr_transaction *read,uint32_t saved[3],uint32_t requested[3])
{
    if(!b||!b->complete||b->error||b->rows>PWRPB_ROWS||!d||!read||!pwrr_retired(read)||!saved||!requested)return 0;
    uint32_t originals[3],targets[3];
    for(unsigned k=0;k<3;k++){
        if(d[k].address!=pwcd_addresses[k]||d[k].length!=32||d[k].index>15||
           pwfi_le(d[k].aux+2*d[k].index,2)<384||
           (d[k].index&&pwfi_le(d[k].aux+2*(d[k].index-1),2)>=384))return 0;
        uint32_t value=read->response[k];
        /* Do not mask unknown response bits or reinterpret an unsupported
         * value as zero. All RAW words and the returned refusal survive. */
        if(value>15||(value&&pwfi_le(d[k].aux+2*value,2)==0))return 0;
        for(unsigned j=0;j<b->rows;j++)if(pwfi_le(b->row[j].raw,4)==d[k].address){
            if(b->row[j].states!=1)return 0;const struct pwrpb_state *s=&b->row[j].state[0];
            if(s->bytes!=72||s->raw[0x10]!=1||s->raw[0x1c]!=1||pwfi_le(s->raw+0x20,4)||
               pwfi_le(s->raw+0xc,4)!=value||pwfi_le(s->raw+0x18,4)!=value)return 0;
        }
        originals[k]=value;targets[k]=d[k].index;
    }
    for(unsigned k=0;k<3;k++){saved[k]=originals[k];requested[k]=targets[k];}return 1;
}
#endif
#endif
