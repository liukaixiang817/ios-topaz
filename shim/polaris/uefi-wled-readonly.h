/* Original Polaris PMI8998 WLED inventory, not a power-control backend.
 * Own DT SID3 d800/d900 and MiCode c7cb50c1 spmi-pmic-arb.c v5.
 * Only observer READ command words are written. Never PMIC/config/IRQ writes.
 * Caller serializes firmware CPU0's EE0 observer access with IRQs masked.
 * Raw identity/config bytes do not authorize writes or prove physical light.
 */
#ifndef POLARIS_EFI_WLED_READONLY_H
#define POLARIS_EFI_WLED_READONLY_H
#include <stdbool.h>
#include <stdint.h>
#define PW_CORE 0u
#define PW_CONFIG 1u
#define PW_OBSERVER 2u
#define PW_CHANNELS 512u
struct polaris_wled_read_bus {
    void *context;
    uint32_t (*read)(void *,unsigned,uint32_t);
    void (*read_command)(void *,uint32_t,uint32_t);
    uint64_t (*now_us)(void *);
    uint32_t version,map[2],owner[2],apid[2],fault,reads;
    uint32_t last_bank,last_reg,last_status,last_polls;
    uint32_t changed_byte_plus_one;uint8_t changed_first,changed_after;
    bool initialized;
};
struct polaris_wled_snapshot {
    uint8_t revision[2][8]; /* ctrl/sink raw peripheral revision, type/subtype */
    uint8_t ctrl[3];       /* display selection, module ready, module enable */
    uint8_t faults[2];     /* fault08 and real-time status10 */
    uint8_t psm[2],irq_enable; /* ctrl5a/5b and IRQ-enable15, READ only */
    uint8_t sink[6];       /* sink enable46, sync47, modulation4a/4b */
    uint8_t string[4][9];  /* mod50+10n through brightness58+10n */
};
enum {PW_E_ARGUMENT=1,PW_E_VERSION,PW_E_MAPPING,PW_E_TIME,
      PW_E_TIMEOUT,PW_E_RESPONSE,PW_E_CHANGED};
static inline bool pw_error(struct polaris_wled_read_bus *b,unsigned e)
{if(b&&!b->fault)b->fault=e;return false;}
static inline bool pw_map(struct polaris_wled_read_bus *b)
{
    if(!b||b->fault||!b->read||!b->read_command||!b->now_us)return pw_error(b,PW_E_ARGUMENT);
    uint32_t version=b->read(b->context,PW_CORE,0);
    if(version<0x50000000u||version>=0x60000000u||
       (b->initialized&&version!=b->version))return pw_error(b,PW_E_VERSION);
    const uint32_t ppid[2]={0x3d8,0x3d9};
    uint32_t apid[2]={UINT32_MAX,UINT32_MAX},map[2]={0,0},owner[2]={0,0};
    for(unsigned a=0;a<PW_CHANNELS;a++) {
        uint32_t v=b->read(b->context,PW_CORE,0x900+4*a);
        for(unsigned k=0;k<2;k++)if(v&&((v>>8)&0xfff)==ppid[k]) {
            uint32_t o=b->read(b->context,PW_CONFIG,0x700+4*a)&7;
            /* Same canonical first match / later EE0 override as own v5. */
            if(apid[k]==UINT32_MAX||o==0){apid[k]=a;map[k]=v;owner[k]=o;}
        }
    }
    for(unsigned k=0;k<2;k++) {
        if(apid[k]==UINT32_MAX || (b->initialized&&
            (b->apid[k]!=apid[k]||b->map[k]!=map[k]||b->owner[k]!=owner[k])))
            return pw_error(b,PW_E_MAPPING);
        b->apid[k]=apid[k];b->map[k]=map[k];b->owner[k]=owner[k];
    }
    b->version=version;b->initialized=true;return true;
}
static inline bool pw_read(struct polaris_wled_read_bus *b,unsigned bank,
    uint8_t reg,uint8_t *out,unsigned count)
{
    if(!b||b->fault)return false;
    if(bank>1||!out||count<1||count>8||count>256u-reg)return pw_error(b,PW_E_ARGUMENT);
    b->last_bank=bank;b->last_reg=reg;b->last_status=0;b->last_polls=0;
    if(!pw_map(b))return false;
    uint32_t offset=0x80*b->apid[bank]; /* EE0 observer, never RW channel */
    uint64_t start=b->now_us(b->context),previous=start;
    if(!start)return pw_error(b,PW_E_TIME);
    b->read_command(b->context,offset,(1u<<27)|((uint32_t)reg<<4)|(count-1));
    for(unsigned n=0;n<4096;n++) {
        uint32_t status=b->read(b->context,PW_OBSERVER,offset+8);
        b->last_status=status;b->last_polls=n+1;
        uint64_t now=b->now_us(b->context);
        if(now<previous)return pw_error(b,PW_E_TIME);
        previous=now;
        if(status&~1u)return pw_error(b,PW_E_RESPONSE);
        if(status==1) {
            uint32_t data[2]={b->read(b->context,PW_OBSERVER,offset+0x18),0};
            if(count>4)data[1]=b->read(b->context,PW_OBSERVER,offset+0x1c);
            for(unsigned i=0;i<count;i++)out[i]=(uint8_t)(data[i/4]>>(8*(i%4)));
            b->reads++;return true;
        }
        if(now-start>=100)return pw_error(b,PW_E_TIMEOUT);
    }
    return pw_error(b,PW_E_TIMEOUT); /* A frozen clock cannot hang USB. */
}
static inline bool pw_collect(struct polaris_wled_read_bus *b,struct polaris_wled_snapshot *s)
{
    if(!pw_read(b,0,0,s->revision[0],8)||!pw_read(b,1,0,s->revision[1],8)||
       !pw_read(b,0,0x44,s->ctrl,3)||!pw_read(b,0,8,s->faults,1)||
       !pw_read(b,0,0x10,s->faults+1,1)||!pw_read(b,1,0x46,s->sink,6)||
       !pw_read(b,0,0x5a,s->psm,2)||!pw_read(b,0,0x15,&s->irq_enable,1))return false;
    /* Nine bytes are split into <=8-byte commands, preserving actual order. */
    for(unsigned n=0;n<4;n++) {
        uint8_t reg=(uint8_t)(0x50+n*0x10);
        if(!pw_read(b,1,reg,s->string[n],8)||!pw_read(b,1,reg+8,s->string[n]+8,1))return false;
    }
    return true;
}
static inline bool polaris_wled_inventory(struct polaris_wled_read_bus *b,
    struct polaris_wled_snapshot *out)
{
    if(!b||!out||b->fault)return pw_error(b,PW_E_ARGUMENT);
    struct polaris_wled_snapshot first={0},after={0};
    if(!pw_collect(b,&first)||!pw_collect(b,&after))return false;
    const uint8_t *a=(const uint8_t *)&first,*c=(const uint8_t *)&after;
    for(unsigned n=0;n<sizeof(first);n++)if(a[n]!=c[n]) {
        b->changed_byte_plus_one=n+1;b->changed_first=a[n];b->changed_after=c[n];
        return pw_error(b,PW_E_CHANGED);
    }
    *out=first;return true; /* Optimistic metadata snapshot, NOT a remote lock. */
}
_Static_assert(sizeof(struct polaris_wled_snapshot)==66,"bounded WLED register inventory v2");
#endif
