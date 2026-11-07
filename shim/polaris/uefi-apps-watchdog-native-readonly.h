/* Own Polaris DT/vendor apps watchdog, native CPU0 inventory only.
 * Separate masked policy: the original unmasked inventory stays unchanged.
 * EN/STS/BARK/BITE reads only; never RST, pet, disable, or secure calls. */
#ifndef POLARIS_APPS_WATCHDOG_NATIVE_READONLY_H
#define POLARIS_APPS_WATCHDOG_NATIVE_READONLY_H
#include "uefi-apps-watchdog-readonly.h"
struct pawn_arch {struct pawr_arch cpu;uint64_t group1,cpacr;};
struct pawn_result {
    uint32_t error,issued,returned,stable;
    struct pawn_arch opening,closing;
    struct pawr_translation translation[8];uint32_t value[2][4];
};
struct pawn_state {
    uint64_t last,first;
    uint32_t snapshots,initial[4];struct pawn_result result;
};
struct pawn_ops {
    void *context;
    int (*arch)(void*,struct pawn_arch*);
    int (*translate)(void*,uint64_t,struct pawr_translation*);
    int (*read32)(void*,uint64_t,uint32_t*);
};
static inline int pawn_valid(const struct pawn_arch*a)
{
    return a->cpu.el==4 && !(a->cpu.mpidr&UINT64_C(0xff00ffffff)) &&
        a->cpu.daif==0xc0 && a->group1==0 && (a->cpu.sctlr&5)==5 &&
        a->cpu.ttbr0 && !(a->cpu.tcr&UINT64_C(0xc080)) &&
        (a->cpu.tcr&63)>=16 && (a->cpu.tcr&63)<=32 && a->cpu.frequency==19200000;
}
static inline int pawn_same(const struct pawn_arch*a,const struct pawn_arch*b)
{
    return pawn_valid(a)&&pawn_valid(b) && a->cpu.el==b->cpu.el &&
        a->cpu.mpidr==b->cpu.mpidr && a->cpu.daif==b->cpu.daif &&
        a->cpu.sctlr==b->cpu.sctlr && a->cpu.tcr==b->cpu.tcr &&
        a->cpu.ttbr0==b->cpu.ttbr0 && a->cpu.ttbr1==b->cpu.ttbr1 &&
        a->cpu.mair==b->cpu.mair && a->cpacr==b->cpacr &&
        b->cpu.ticks>=a->cpu.ticks && b->cpu.ticks-a->cpu.ticks<=384000;
}
static inline int pawn_run(const void*map,uint64_t bytes,uint64_t capacity,
    uint64_t stride,uint32_t version,const struct pawn_arch*bound,
    const struct pawn_ops*ops,struct pawn_result*r)
{
    if(!r)return 0;*r=(struct pawn_result){0};
    struct polaris_efi_memory memory={0};
    if(version!=1||!polaris_efi_memory_check(map,bytes,capacity,stride,&memory)){
        r->error=1;return 0;
    }
    for(uint64_t at=0;at<bytes;at+=stride){
        const struct efi_memory*m=(const void*)((const uint8_t*)map+at);
        if(m->physical<=PAWR_BASE && m->physical+m->pages*4096>=PAWR_BASE+4096 &&
           (m->type!=11||!(m->attributes&1)||(m->attributes&8))){r->error=2;return 0;}
    }
    if(!bound||!pawn_valid(bound)||!ops||!ops->arch||!ops->translate||!ops->read32||
       !ops->arch(ops->context,&r->opening)||!pawn_same(bound,&r->opening)){
        r->error=3;return 0;
    }
    static const unsigned offset[4]={8,12,16,20};
    for(unsigned n=0;n<8;n++){
        struct pawn_arch live={0};struct pawr_translation*t=&r->translation[n];
        if(!ops->arch(ops->context,&live)||!pawn_same(&r->opening,&live)){
            r->error=4;return 0;
        }
        if(!ops->translate(ops->context,PAWR_BASE+offset[n%4],t)||
           t->saved!=t->restored||(t->par&1)||!(t->par&0x200)||
           ((t->par>>56)!=0&&(t->par>>56)!=4)||
           (t->par&UINT64_C(0x0000fffffffff000))!=PAWR_BASE){r->error=5;return 0;}
        if(!ops->arch(ops->context,&live)||!pawn_same(&r->opening,&live)){
            r->error=4;return 0;
        }
        r->issued++;
        if(!ops->read32(ops->context,PAWR_BASE+offset[n%4],&r->value[n/4][n%4])){
            r->error=6;return 0;
        }r->returned++;
    }
    if(!ops->arch(ops->context,&r->closing)||!pawn_same(&r->opening,&r->closing)){
        r->error=4;return 0;
    }
    r->stable=r->value[0][0]==r->value[1][0]&&r->value[0][2]==r->value[1][2]&&
        r->value[0][3]==r->value[1][3];
    if(!r->stable){r->error=7;return 0;}return 1;
}
#endif
