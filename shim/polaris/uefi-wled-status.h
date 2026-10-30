/* Explicit OEM status witness for the Polaris WLED sequencer. Not a health
 * check or permission to change current/voltage/protection. Qualcomm's WLED
 * IRQ enum and irq_status map ILIM/OVP/SC to RT bits 0/1/2. Own MiCode's normal
 * module_en does not require the two volatile status bytes to remain equal;
 * its OVP handler records ILIM and acts on OVP. Preserve every read of ILIM,
 * reject all other bits, and still compare ALL static configuration bytes.
 * This policy has no MMIO mapping, writer, retry or fault-clear operation.
 */
#ifndef POLARIS_EFI_WLED_STATUS_H
#define POLARIS_EFI_WLED_STATUS_H
#include <stddef.h>
#include "uefi-wled-readonly.h"
#define PWS_RECORDS 64u
#define PWS_MAX_CHECK_US UINT64_C(200000)
enum {PWS_E_ARGUMENT=64,PWS_E_STATUS,PWS_E_CONFIG,PWS_E_TIME,PWS_E_CAPACITY};
struct polaris_wled_status_record {
    uint64_t began_us,ended_us;
    uint8_t fault,rt,valid,reserved;
};
struct polaris_wled_status_witness {
    struct polaris_wled_status_record record[PWS_RECORDS];
    uint64_t previous_us;
    unsigned count,error;
    uint8_t fault_or,rt_or;
};
static inline bool pws_fail(struct polaris_wled_status_witness *w,unsigned error)
{if(w&&!w->error)w->error=error;return false;}
static inline bool pws_static_equal(const struct polaris_wled_snapshot *a,
    const struct polaris_wled_snapshot *b)
{
    /* Never zero or rewrite either raw snapshot to manufacture equality. */
    const uint8_t *x=(const uint8_t *)a,*y=(const uint8_t *)b;
    for(unsigned n=0;n<sizeof(*a);n++) {
        if(n==offsetof(struct polaris_wled_snapshot,faults)||
           n==offsetof(struct polaris_wled_snapshot,faults)+1)continue;
        if(x[n]!=y[n])return false;
    }
    return true;
}
static inline bool pws_status(struct polaris_wled_status_witness *w,
    struct polaris_wled_read_bus *b,struct polaris_wled_status_record *r)
{
    /* Read statuses first and retain even a partial/severe observation. No
     * majority vote, last-word substitution, equality requirement or retry. */
    if(!pw_read(b,0,8,&r->fault,1))return pws_fail(w,b->fault);
    r->valid=1;w->fault_or|=r->fault;
    if(r->fault&~1u)return pws_fail(w,PWS_E_STATUS);
    if(!pw_read(b,0,0x10,&r->rt,1))return pws_fail(w,b->fault);
    r->valid|=2;w->rt_or|=r->rt;
    if(r->rt&~1u)return pws_fail(w,PWS_E_STATUS);
    return true;
}
static inline bool pws_collect(struct polaris_wled_status_witness *w,
    struct polaris_wled_read_bus *b,struct polaris_wled_snapshot *s)
{
    if(w->count>=PWS_RECORDS)return pws_fail(w,PWS_E_CAPACITY);
    struct polaris_wled_status_record *r=&w->record[w->count++];
    uint64_t began=b->now_us(b->context);r->began_us=began;
    if(!began||began<w->previous_us)return pws_fail(w,PWS_E_TIME);
    bool ok=pws_status(w,b,r);
    s->faults[0]=r->fault;s->faults[1]=r->rt;
    if(ok)ok=pw_read(b,0,0,s->revision[0],8)&&pw_read(b,1,0,s->revision[1],8)&&
        pw_read(b,0,0x44,s->ctrl,3)&&pw_read(b,1,0x46,s->sink,6)&&
        pw_read(b,0,0x5a,s->psm,2)&&pw_read(b,0,0x15,&s->irq_enable,1);
    for(unsigned n=0;ok&&n<4;n++) {
        uint8_t reg=(uint8_t)(0x50+n*0x10);
        ok=pw_read(b,1,reg,s->string[n],8)&&pw_read(b,1,reg+8,s->string[n]+8,1);
    }
    uint64_t end=b->now_us(b->context);r->ended_us=end;
    if(!end||end<=began||end-began>PWS_MAX_CHECK_US||end<w->previous_us)
        return pws_fail(w,PWS_E_TIME);
    w->previous_us=end;
    if(!ok)return pws_fail(w,b->fault?b->fault:PWS_E_STATUS);
    return true;
}
static inline bool pws_verify(struct polaris_wled_status_witness *w,
    struct polaris_wled_read_bus *b,const struct polaris_wled_snapshot *expected)
{
    if(!w||w->error||!b||b->fault||!b->now_us||!expected)
        return pws_fail(w,PWS_E_ARGUMENT);
    uint64_t began=b->now_us(b->context);
    if(!began||began<w->previous_us)return pws_fail(w,PWS_E_TIME);
    struct polaris_wled_snapshot first={0},after={0};
    if(!pws_collect(w,b,&first)||!pws_static_equal(&first,expected))
        return pws_fail(w,PWS_E_CONFIG);
    if(!pws_collect(w,b,&after)||!pws_static_equal(&after,expected)||
       !pws_static_equal(&first,&after))return pws_fail(w,PWS_E_CONFIG);
    uint64_t end=b->now_us(b->context);
    if(end<w->previous_us||end-began>PWS_MAX_CHECK_US)return pws_fail(w,PWS_E_TIME);
    w->previous_us=end;return true;
}
_Static_assert(offsetof(struct polaris_wled_snapshot,faults)==19,"exact status scope");
#endif
