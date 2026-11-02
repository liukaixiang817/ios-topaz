/* Same-session four-VRM data and pure prefix checks. No callback, ticket,
 * client-held flag or literal address here grants physical access. */
#ifndef POLARIS_UEFI_WIFI_VRM_DOMAIN_H
#define POLARIS_UEFI_WIFI_VRM_DOMAIN_H
#ifndef EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
#define EFI_XNU_WIFI_FOUR_VRM_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "../../tools/polaris-wifi-vrm-read.h"
#include "../../tools/polaris-wifi-vrm-transaction.h"
static const uint8_t pwv_names[4][8]={{'l','d','o','a','5',0,0,0},{'l','d','o','a','7',0,0,0},
    {'l','d','o','a','1','7',0,0},{'l','d','o','a','2','5',0,0}};
/* Reuse the current complete CmdDb format validator. This selects four more
 * entries in its validated table footprint; it is not another DB parser. */
static inline int pwv_select_bytes(const uint8_t b[PWCD_DB_BYTES],struct pwcd_resource out[4])
{
    struct pwcd_resource arc[3];unsigned found[4]={0};
    if(!pwcd_select_bytes(b,arc))return 0;
    for(unsigned group=0;group<8;group++){
        const uint8_t*h=b+8+16*group;unsigned id=(unsigned)pwfi_le(h,2),off=(unsigned)pwfi_le(h+2,2),aux=(unsigned)pwfi_le(h+4,2),count=(unsigned)pwfi_le(h+6,2);
        if(!count)continue;
        for(unsigned n=0;n<count;n++){
            unsigned at=144+off+24*n;const uint8_t*e=b+at;
            for(unsigned k=0;k<4;k++)if(pgcd_equal(e,pwv_names[k],8)){
                struct pwcd_resource*r=&out[k];
                if(++found[k]!=1||id!=4||pwfi_le(h+8,2)!=0||pwfi_le(e+20,2)!=0||
                   pwfi_le(e+16,4)!=pwvm_addresses[k])return 0;
                r->entry=at;r->aux_offset=144+aux+(unsigned)pwfi_le(e+22,2);r->address=(uint32_t)pwfi_le(e+16,4);
                r->priority[0]=(uint32_t)pwfi_le(e+8,4);r->priority[1]=(uint32_t)pwfi_le(e+12,4);
                r->version=r->length=0;r->index=UINT32_MAX;
                if(r->aux_offset>PWCD_DB_BYTES)return 0;pgcd_copy(r->entry_raw,e,24);
                for(unsigned j=0;j<32;j++)r->aux[j]=0;
            }
        }
    }
    return found[0]==1&&found[1]==1&&found[2]==1&&found[3]==1;
}
struct pwv_result {
    uint32_t attempted,error,unknown,phase,engines_retired,known_refusal;
    uint64_t provider,core,prepared,access;
    struct pwcd_resource resources[3][4];
    struct pwvr_transaction read;
    struct pwvm_transaction write;
};
enum pwv_error {PWV_OK,PWV_ARGUMENT,PWV_SOURCE,PWV_READ,PWV_VALUES,PWV_WRITE,PWV_PREFIX,PWV_TIME};
static inline int pwv_plan(const struct pwv_result*r,struct pwvm_rail rail[4])
{
    if(!r||!pwvr_retired(&r->read))return 0;
    for(unsigned k=0;k<4;k++){
        const struct pwcd_resource*d=&r->resources[1][k];
        if(d->address!=pwvm_addresses[k]||d->version||d->length||d->index!=UINT32_MAX)return 0;
        rail[k]=(struct pwvm_rail){d->address,r->read.response[4*k],r->read.response[4*k+1],r->read.response[4*k+2],pwvm_min_mV[k]};
        if(r->read.response[4*k+3]>511)return 0; /* Preserve full raw; never mask. */
    }
    return pwvm_inputs(rail);
}
static inline int pwv_engine_prefix(const struct pwv_result*r)
{
    if(!r||!r->attempted||r->unknown||!pwvr_retired(&r->read)||
       !pgcd_equal(r->resources[0],r->resources[1],sizeof(r->resources[0])))return 0;
    if(r->known_refusal){
        const unsigned char*p=(const void*)&r->write;
        for(unsigned k=0;k<sizeof(r->write);k++)if(p[k])return 0;
        return r->error==PWV_VALUES;
    }
    struct pwvm_rail expected[4];
    if(r->error||!pwv_plan(r,expected)||!pwvm_retired(&r->write)||
       !pgcd_equal(expected,r->write.rail,sizeof(expected)))return 0;
    const struct pwrsc_transaction *a=&r->read.io,*b=&r->write.io;
    return a->tcs==b->tcs&&a->IRQ_enable==b->IRQ_enable&&a->active_mask==b->active_mask&&
        pgcd_equal(&a->observed,&b->saved,sizeof(b->saved))&&b->started>=a->last&&b->last>=a->started&&
        b->last-a->started<=PWRSC_DEADLINE&&a->steps+b->steps<=256&&a->events+b->events<=PWRSC_HISTORY;
}
#endif
#endif
