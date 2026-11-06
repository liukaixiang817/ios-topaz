/* Only the two own-DT/vendor MSS pages in a previously invalid L2 slot.
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
    uint64_t table,entry,value;
    uint32_t attempted,error,issued,returned,installed,complete,read_error,reserved;
    uint8_t storage[8191];
};
#define PMBM_LEAF_FLAGS UINT64_C(0x0060000000000603) /* PXN/UXN, AF, outer SH, Device0, EL1 RW */
static inline uint64_t pmbm_leaf(unsigned index)
{return index==128?(UINT64_C(0x4080000)|PMBM_LEAF_FLAGS):index==384?(UINT64_C(0x4180000)|PMBM_LEAF_FLAGS):0;}
static inline int pmbm_hole(const struct pmpt_walk*w,uint64_t table)
{
    if((w->tcr&~UINT64_C(63))!=UINT64_C(0x280803500)||(w->tcr&63)<16||(w->tcr&63)>24||w->address!=UINT64_C(0x4080000)||
       w->attempted!=1||w->first||w->levels!=3||w->error!=3||w->stable!=1||w->complete||
       w->descriptor[2]||!table||(table&4095)||(table>>40))return 0;
    for(unsigned n=0;n<2;n++)if(w->descriptor[n]!=(w->descriptor[n]&UINT64_C(0x0000fffffffff000))+3)return 0;
    for(unsigned n=0;n<3;n++)if((w->entry[n]&~UINT64_C(4095))==table)return 0;
    return 1;
}
static inline int pmbm_current(const struct pmbm_state*m)
{
    if(!m->complete||m->error)return 0;
    if(!m->installed)return !m->issued;
    if(m->installed!=1||m->issued!=1||m->returned!=1||m->value!=(m->table|3))return 0;
    for(unsigned n=0;n<3;n++)if(*(const volatile uint64_t*)(uintptr_t)m->walk.entry[n]!=(n==2?m->value:m->walk.descriptor[n]))return 0;
    const volatile uint64_t*t=(const void*)(uintptr_t)m->table;
    for(unsigned n=0;n<512;n++)if(t[n]!=pmbm_leaf(n))return 0;
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
    for(uint64_t at=m->table;at<m->table+4096;at+=line)__asm__ volatile("dc cvac,%0"::"r"(at):"memory");
    __asm__ volatile("dsb sy":::"memory");
    /* One exclusive attempt, only zero -> table. A changed entry is never overwritten. */
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
