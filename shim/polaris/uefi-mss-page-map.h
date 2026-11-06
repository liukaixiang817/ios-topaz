/* Own-DT/vendor QDSP/RMB pair or PDC/restart: invalid L2, or one invalid L3 leaf.
 * CPU0 exclusion and source qualification belong to the composed owner.
 * No allocation, firmware service, MMIO, valid-mapping replacement or undo.
 * The linked writable BSS table remains resident with the native parent. */
#ifndef POLARIS_UEFI_MSS_PAGE_MAP_H
#define POLARIS_UEFI_MSS_PAGE_MAP_H
#ifndef EFI_XNU_MSS_PAGE_MAP_AVAILABLE
#define EFI_XNU_MSS_PAGE_MAP_AVAILABLE 0
#endif
#if EFI_XNU_MSS_PAGE_MAP_AVAILABLE
struct pmbm_state {
    struct pmpt_walk walk;
    struct pmli_read source[2][4];
    struct pmni_translation before[2],after[2];
    struct pwmc_translation storage_AT;
    struct pmni_arch architecture,final_architecture;
    struct pmrg_target target[2];
    uint64_t table,entry,value,base;
    uint32_t attempted,error,issued,returned,installed,complete,read_error,level;
    uint8_t storage[8191];
};
#define PMBM_LEAF_FLAGS UINT64_C(0x0060000000000603) /* PXN/UXN, AF, outer SH, Device0, EL1 RW */
static inline unsigned pmbm_pages(uint64_t base)
{return base==UINT64_C(0x4080000)?2:(base==UINT64_C(0xb2e0000)||base==UINT64_C(0xc2b0000))?1:0;}
static inline uint64_t pmbm_leaf(uint64_t base,unsigned index)
{
    if(base==UINT64_C(0xb2e0000)||base==UINT64_C(0xc2b0000))return index==((base>>12)&511)?(base|PMBM_LEAF_FLAGS):0;
    if(base!=UINT64_C(0x4080000))return 0;
    return index==128?(base|PMBM_LEAF_FLAGS):index==384?(UINT64_C(0x4180000)|PMBM_LEAF_FLAGS):0;
}
/* Return the zero descriptor level; never replace any nonzero descriptor.
 * A pre-existing L3 is supported only for the single own PDC or restart page. */
static inline unsigned pmbm_hole(const struct pmpt_walk*w,uint64_t table)
{
    if((w->tcr&~UINT64_C(63))!=UINT64_C(0x280803500)||(w->tcr&63)<16||(w->tcr&63)>24||!pmbm_pages(w->address)||
       w->attempted!=1||w->first||(w->levels!=3&&w->levels!=4)||w->error!=3||w->stable!=1||w->complete)return 0;
    unsigned level=w->levels-1;
    if((level==3&&pmbm_pages(w->address)!=1)||w->descriptor[level])return 0;
    for(unsigned n=0;n<level;n++)if(w->descriptor[n]!=(w->descriptor[n]&UINT64_C(0x0000fffffffff000))+3)return 0;
    if(level==2){
        if(!table||(table&4095)||(table>>40))return 0;
        for(unsigned n=0;n<3;n++)if((w->entry[n]&~UINT64_C(4095))==table)return 0;
    }
    return level;
}
static inline int pmbm_current(const struct pmbm_state*m)
{
    if(!m->complete||m->error||!pmbm_pages(m->base))return 0;
    if(!m->installed)return !m->issued;
    if(m->installed!=1||m->issued!=1||m->returned!=1||(m->level!=2&&m->level!=3)||
       m->walk.levels!=m->level+1||m->entry!=m->walk.entry[m->level])return 0;
    if(m->level==2){if(m->value!=(m->table|3))return 0;}
    else if(pmbm_pages(m->base)!=1||m->value!=(m->base|PMBM_LEAF_FLAGS)||
       m->table!=(m->walk.descriptor[2]&UINT64_C(0x0000fffffffff000)))return 0;
    for(unsigned n=0;n<=m->level;n++)if(*(const volatile uint64_t*)(uintptr_t)m->walk.entry[n]!=(n==m->level?m->value:m->walk.descriptor[n]))return 0;
    if(m->level==2){
        const volatile uint64_t*t=(const void*)(uintptr_t)m->table;
        for(unsigned n=0;n<512;n++)if(t[n]!=pmbm_leaf(m->base,n))return 0;
    }
    return 1;
}
#if defined(POLARIS_MSS_PAGE_MAP_SOFTWARE_PEER)
static int pmbm_publish(struct pmbm_state*);
#else
static inline int pmbm_publish(struct pmbm_state*m)
{
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t ctr,observed;uint32_t failed;
    __asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));
    uint64_t line=UINT64_C(4)<<((ctr>>16)&15);if(line<16||line>4096)return 0;
    if(m->level==2)for(uint64_t at=m->table;at<m->table+4096;at+=line)__asm__ volatile("dc cvac,%0"::"r"(at):"memory");
    __asm__ volatile("dsb sy":::"memory");
    /* One exclusive attempt, only zero -> table or exact own single leaf. A changed entry is never overwritten. */
    m->issued=1;
    __asm__ volatile("ldxr %0,[%2]; cbnz %0,1f; stxr %w1,%3,[%2]; b 2f; 1: clrex; mov %w1,#1; 2:"
        :"=&r"(observed),"=&r"(failed):"r"(m->entry),"r"(m->value):"memory");
    m->returned=1;if(failed||observed)return 0;m->installed=1;
    __asm__ volatile("dc cvac,%0; dsb ish; tlbi vmalle1is; dsb ish; isb"::"r"(m->entry):"memory");
    return 1;
#else
    (void)m;return 0;
#endif
}
#endif
#endif
#endif
