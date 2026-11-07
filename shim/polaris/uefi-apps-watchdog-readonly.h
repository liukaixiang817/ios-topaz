/* Polaris apps watchdog inventory only. Own pinned MiCode source c7cb50c:
 * arch/arm64/boot/dts/qcom/sdm845.dtsi: wdt@17980000;
 * drivers/soc/qcom/watchdog_v2.c: EN=8,STS=c,BARK=10,BITE=14.
 * No reset/pet/enable writes, page-table edits or ownership transfer. */
#ifndef POLARIS_UEFI_APPS_WATCHDOG_READONLY_H
#define POLARIS_UEFI_APPS_WATCHDOG_READONLY_H
#include "uefi-memory.h"
#define PAWR_BASE UINT64_C(0x17980000)
struct pawr_arch {
    uint64_t el,mpidr,daif,sctlr,tcr,ttbr0,ttbr1,mair,frequency,ticks;
};
struct pawr_translation {uint64_t saved,par,restored;};
struct pawr_ops {
    void *context;
    int (*arch)(void *,struct pawr_arch *);
    int (*translate)(void *,uint64_t,struct pawr_translation *);
    int (*read32)(void *,uint64_t,uint32_t *);
};
struct pawr_result {
    uint32_t error,issued,returned,stable,map_present;
    uint64_t map_type,map_base,map_pages,map_attributes;
    struct pawr_arch opening,closing;
    struct pawr_translation translation[8];
    uint32_t value[2][4];
};
static inline int pawr_arch_valid(const struct pawr_arch *a)
{
    return a->el==4 && !(a->mpidr&UINT64_C(0xff00ffffff)) &&
        !(a->daif&0x80) && (a->sctlr&1) && a->ttbr0 &&
        !(a->tcr&UINT64_C(0xc080)) && (a->tcr&63)>=16 &&
        (a->tcr&63)<=32 && a->frequency==19200000;
}
static inline int pawr_arch_same(const struct pawr_arch *a,const struct pawr_arch *b)
{
    return pawr_arch_valid(b) && a->el==b->el && a->mpidr==b->mpidr &&
        a->daif==b->daif && a->sctlr==b->sctlr && a->tcr==b->tcr &&
        a->ttbr0==b->ttbr0 && a->ttbr1==b->ttbr1 && a->mair==b->mair &&
        b->ticks>=a->ticks && b->ticks-a->ticks<=a->frequency/50;
}
static inline int pawr_run(const void *map,uint64_t bytes,uint64_t capacity,
    uint64_t stride,uint32_t version,const struct pawr_ops *ops,struct pawr_result *r)
{
    if(!r)return 0;
    *r=(struct pawr_result){0};
    struct polaris_efi_memory memory={0};
    if(version!=1 || !polaris_efi_memory_check(map,bytes,capacity,stride,&memory)){
        r->error=1;return 0;
    }
    for(uint64_t at=0;at<bytes;at+=stride){
        const struct efi_memory *m=(const void *)((const uint8_t *)map+at);
        if(m->physical<=PAWR_BASE && m->physical+m->pages*4096>=PAWR_BASE+4096){
            r->map_present=1;
            r->map_type=m->type;r->map_base=m->physical;
            r->map_pages=m->pages;r->map_attributes=m->attributes;
        }
    }
    /* EFI maps may omit peripheral ranges (the own-phone retained map does).
     * A listed RAM/reserved range is refused. An omitted range is admitted
     * ONLY at this own-DT fixed address and after Device/NS/identity AT below;
     * this grants no allocation, GCD registration or write ownership. */
    if(r->map_present && (r->map_type!=11 || !(r->map_attributes&1) || (r->map_attributes&8))){
        r->error=2;return 0;
    }
    if(!ops || !ops->arch || !ops->translate || !ops->read32 ||
       !ops->arch(ops->context,&r->opening) || !pawr_arch_valid(&r->opening)){
        r->error=3;return 0;
    }
    static const uint32_t offset[4]={8,12,16,20};
    for(unsigned n=0;n<8;n++){
        struct pawr_arch live={0};struct pawr_translation *t=&r->translation[n];
        if(!ops->arch(ops->context,&live) || !pawr_arch_same(&r->opening,&live)){
            r->error=4;return 0;
        }
        if(!ops->translate(ops->context,PAWR_BASE+offset[n%4],t) ||
           t->saved!=t->restored || (t->par&1) || !(t->par&0x200) ||
           ((t->par>>56)!=0 && (t->par>>56)!=4) ||
           (t->par&UINT64_C(0x0000fffffffff000))!=PAWR_BASE){
            r->error=5;return 0;
        }
        if(!ops->arch(ops->context,&live) || !pawr_arch_same(&r->opening,&live)){
            r->error=4;return 0;
        }
        r->issued++;
        if(!ops->read32(ops->context,PAWR_BASE+offset[n%4],&r->value[n/4][n%4])){
            r->error=6;return 0;
        }
        r->returned++;
    }
    if(!ops->arch(ops->context,&r->closing) || !pawr_arch_same(&r->opening,&r->closing)){
        r->error=4;return 0;
    }
    /* STS is a live counter; the configuration must agree across both passes. */
    r->stable=r->value[0][0]==r->value[1][0] &&
        r->value[0][2]==r->value[1][2] && r->value[0][3]==r->value[1][3];
    if(!r->stable){r->error=7;return 0;}
    return 1;
}
#endif
