/* Polaris GMU kernel stream5, SMMUv2 stage1. Sources: captured polaris DT,
 * MiCode c7cb50c1 arm-smmu.c/io-pgtable-arm.c. Contexts5..7 are protected;
 * preserve every other stream/context. qcom,disable-atos is mandatory:
 * never issue ATS1PR, even for a translation test. Real HFI completion must
 * establish device DMA, not a software page-table walk.
 * Caller owns GPU power/clocks and holds both GMU and 3D processors stopped.
 * All backing pages stay resident through success, failure and cleanup.
 */
#ifndef POLARIS_A630_SMMU_H
#define POLARIS_A630_SMMU_H
#ifndef POLARIS_A630_MMU_H
#error Include Polaris translation table definitions first
#endif
#define A630_SMMU_BYTES 0x10000u
#define A630_SMMU_POLLS 500000u
#define A630_SMMU_STREAM 5u
#define A630_SMMU_IMPLS 12u
enum a630_smmu_error {
    A630_SMMU_DISABLED, A630_SMMU_ARGUMENT, A630_SMMU_LEASE,
    A630_SMMU_IO, A630_SMMU_LAYOUT, A630_SMMU_OWNERSHIP,
    A630_SMMU_ACK, A630_SMMU_TLB, A630_SMMU_READY, A630_SMMU_RESTORE
};
struct a630_smmu_io {
    bool (*stopped)(void *); /* live exclusive lease, GMU/3D halted */
    bool (*read)(void *, uint32_t, uint32_t *);
    bool (*write)(void *, uint32_t, uint32_t);
    bool (*read64)(void *, uint32_t, uint64_t *);
    bool (*write64)(void *, uint32_t, uint64_t);
    bool (*clean)(void *, const void *, size_t);
    bool (*sync)(void *);
    void (*wait)(void *, uint32_t);
};
struct a630_smmu_snapshot {
    uint32_t error, start_error, stage, changed, restored;
    uint32_t id[4], page, banks, stage2_banks, matches, half;
    uint32_t slot, bank, context, global, smr, s2cr, cbar, cba2r, foreign;
    uint32_t control[5], impl[A630_SMMU_IMPLS];
    uint64_t ttbr[2], root;
    uint32_t failed_offset, expected, actual, polls, restore_error;
};
static const uint32_t a630_smmu_impl_offsets[A630_SMMU_IMPLS] = {
    0x6000,0x6060,0x678c,0x6794,0x6800,0x6900,
    0x6924,0x6928,0x6930,0x6960,0x6b64,0x6b68
};
static const uint32_t a630_smmu_impl_values[A630_SMMU_IMPLS] = {
    0x2378,0x1055,8,0x28,6,0x3ff,0x204,0x11000,0x800,0xffffffff,0x1a5551,0x9a82a382
};
/* SCTLR, TCR2, TCR, MAIR0, MAIR1. TTBRs use atomic64 accesses separately. */
static const uint32_t a630_smmu_control[5] = {0,0x10,0x30,0x38,0x3c};
static inline bool a630_smmu_lease(const struct a630_smmu_io *io, void *ctx,
                                 struct a630_smmu_snapshot *s)
{
    if (io->stopped(ctx)) return true;
    s->error = A630_SMMU_LEASE; return false;
}
static inline bool a630_smmu_rd(const struct a630_smmu_io *io, void *ctx,
    struct a630_smmu_snapshot *s, uint32_t off, uint32_t *value)
{
    if (!a630_smmu_lease(io,ctx,s)) return false;
    if (io->read(ctx,off,value)) return true;
    s->error = A630_SMMU_IO; s->failed_offset = off; return false;
}
static inline bool a630_smmu_set(const struct a630_smmu_io *io, void *ctx,
    struct a630_smmu_snapshot *s, uint32_t off, uint32_t value, uint32_t mask)
{
    if (!a630_smmu_lease(io,ctx,s)) return false;
    s->changed = 1; /* Includes a write callback failing after a posted write. */
    if (!io->write(ctx,off,value)) {
        s->error = A630_SMMU_IO; s->failed_offset = off; return false;
    }
    uint32_t actual;
    if (!a630_smmu_rd(io,ctx,s,off,&actual)) return false;
    if ((actual ^ value) & mask) {
        s->error = A630_SMMU_ACK; s->failed_offset = off;
        s->expected = value; s->actual = actual; return false;
    }
    return true;
}
static inline bool a630_smmu_set64(const struct a630_smmu_io *io, void *ctx,
    struct a630_smmu_snapshot *s, uint32_t off, uint64_t value)
{
    if (!a630_smmu_lease(io,ctx,s)) return false;
    uint64_t actual = 0; s->changed = 1;
    if (!io->write64(ctx,off,value)) {
        s->error = A630_SMMU_IO; s->failed_offset = off; return false;
    }
    if (!a630_smmu_lease(io,ctx,s)) return false;
    if (!io->read64(ctx,off,&actual)) {
        s->error = A630_SMMU_IO; s->failed_offset = off; return false;
    }
    if (actual != value) {
        s->error = A630_SMMU_ACK; s->failed_offset = off;
        s->expected = (uint32_t)value; s->actual = (uint32_t)actual; return false;
    }
    return true;
}
static inline bool a630_smmu_tlb(const struct a630_smmu_io *io, void *ctx,
    struct a630_smmu_snapshot *s)
{
    if (!a630_smmu_lease(io,ctx,s)) return false;
    if (!io->write(ctx,s->context+0x610,s->bank) ||
        !io->write(ctx,s->context+0x7f0,0) || !io->sync(ctx)) {
        s->error = A630_SMMU_IO; return false;
    }
    uint32_t value = 0;
    for (unsigned i=0;i<A630_SMMU_POLLS;i++) {
        s->polls++;
        if (!a630_smmu_rd(io,ctx,s,s->context+0x7f4,&value)) return false;
        if (!(value&1)) return true;
        io->wait(ctx,1);
    }
    s->error = A630_SMMU_TLB; s->failed_offset = s->context+0x7f4;
    s->expected = 0; s->actual = value; return false;
}
/* Geometry alone never authorizes MMIO. The outer adapter gates these
 * parsed values against exact DT ranges and stopped processor ownership. */
static inline bool a630_smmu_geometry(struct a630_smmu_snapshot *s)
{
    if (!(s->id[0]&(1u<<30)) || !(s->id[0]&(1u<<27)) ||
        !(s->id[2]&(1u<<12)) || (s->id[1]&(1u<<31))) return false;
    s->page = 4096; s->banks = s->id[1]&255;
    s->stage2_banks = (s->id[1]>>16)&255;
    s->matches = s->id[0]&255;
    s->half = (2u << ((s->id[1]>>28)&7))*s->page;
    unsigned oas=(s->id[2]>>4)&15, ubs=(s->id[2]>>8)&15;
    return s->half == A630_SMMU_BYTES/2 && s->banks>1 &&
        s->banks<=s->half/s->page && s->stage2_banks<s->banks &&
        s->matches && s->matches<=128 && ((s->id[0]>>9)&15)>=3 &&
        oas>=1 && oas<=5 && ubs>=2 && ubs<=5;
}
static inline bool a630_smmu_callbacks(const struct a630_smmu_io *io)
{
    return io && io->stopped && io->read && io->write && io->read64 && io->write64 &&
        io->clean && io->sync && io->wait;
}
static inline enum a630_smmu_error
a630_smmu_begin(bool exact_board, bool atos_disabled, struct a630_mmu *tables,
    const struct a630_smmu_io *io, void *ctx, struct a630_smmu_snapshot *s)
{
    if (!s) return A630_SMMU_ARGUMENT;
    *s=(struct a630_smmu_snapshot){.slot=UINT32_MAX,.bank=UINT32_MAX};
    if (!exact_board) return A630_SMMU_DISABLED;
    if (!atos_disabled || !a630_smmu_callbacks(io) || !a630_mmu_valid(tables)) {
        s->error=A630_SMMU_ARGUMENT; goto done;
    }
    s->stage=1;
    for (unsigned n=0;n<4;n++)
        if (!a630_smmu_rd(io,ctx,s,n==3?0x3c:0x20+4*n,&s->id[n])) goto done;
    if (!a630_smmu_geometry(s)) {s->error=A630_SMMU_LAYOUT;goto done;}
    s->stage=2;
    uint32_t used=1, free_slot=UINT32_MAX;
    for (unsigned n=0;n<s->matches;n++) {
        uint32_t smr,s2cr;
        if (!a630_smmu_rd(io,ctx,s,0x800+4*n,&smr) ||
            !a630_smmu_rd(io,ctx,s,0xc00+4*n,&s2cr)) goto done;
        if (!(smr&(1u<<31))) {if(free_slot==UINT32_MAX)free_slot=n;continue;}
        unsigned mask=(smr>>16)&0x7fff, id=smr&0x7fff;
        if (!((A630_SMMU_STREAM^id)&~mask)) {
            /* An overlapping/wildcard match could affect another stream. */
            if (mask || s->slot!=UINT32_MAX) {s->error=A630_SMMU_OWNERSHIP;goto done;}
            s->slot=n; s->smr=smr; s->s2cr=s2cr;
        } else if (((s2cr>>16)&3)==0) {
            s->foreign=1;
            if ((s2cr&255)<32) used|=1u<<(s2cr&255);
        }
    }
    if (s->slot==UINT32_MAX) {
        if (free_slot==UINT32_MAX) {s->error=A630_SMMU_OWNERSHIP;goto done;}
        s->slot=free_slot;
        if (!a630_smmu_rd(io,ctx,s,0x800+4*s->slot,&s->smr) ||
            !a630_smmu_rd(io,ctx,s,0xc00+4*s->slot,&s->s2cr)) goto done;
    }
    /* CB0 is reserved for the later 3D context;5..7 belong to HYP. */
    for (unsigned n=1;n<s->banks && n<5;n++) {
        uint32_t control;
        if (n<s->stage2_banks || used&(1u<<n)) continue;
        if (!a630_smmu_rd(io,ctx,s,s->half+n*s->page,&control)) goto done;
        if (!(control&1)) {s->bank=n;s->context=s->half+n*s->page;break;}
    }
    if (s->bank==UINT32_MAX) {s->error=A630_SMMU_OWNERSHIP;goto done;}
    s->stage=3;
    if (!a630_smmu_rd(io,ctx,s,0,&s->global) ||
        !a630_smmu_rd(io,ctx,s,s->page+4*s->bank,&s->cbar) ||
        !a630_smmu_rd(io,ctx,s,s->page+0x800+4*s->bank,&s->cba2r)) goto done;
    for (unsigned n=0;n<5;n++)
        if (!a630_smmu_rd(io,ctx,s,s->context+a630_smmu_control[n],&s->control[n])) goto done;
    if (!a630_smmu_lease(io,ctx,s)) goto done;
    if (!io->read64(ctx,s->context+0x20,&s->ttbr[0]) ||
        !io->read64(ctx,s->context+0x28,&s->ttbr[1])) {s->error=A630_SMMU_IO;goto done;}
    for (unsigned n=0;n<A630_SMMU_IMPLS;n++)
        if (!a630_smmu_rd(io,ctx,s,a630_smmu_impl_offsets[n],&s->impl[n])) goto done;
    /* Shared implementation registers may not be changed under another
     * stream. An existing translation owner must already have installed the
     * board values, and the global fault/enable policy must already match. */
    if (s->foreign) {
        if ((s->global&0x401)!=0x400) {s->error=A630_SMMU_OWNERSHIP;goto done;}
        for (unsigned n=0;n<A630_SMMU_IMPLS;n++)
            if (s->impl[n]!=a630_smmu_impl_values[n]) {s->error=A630_SMMU_OWNERSHIP;goto done;}
    }
    if (!a630_smmu_lease(io,ctx,s)) goto done;
    if (!io->clean(ctx,tables->memory,(size_t)tables->used*4096) || !io->sync(ctx)) {
        s->error=A630_SMMU_IO;goto done;
    }
    s->stage=4;
    /* Make this stream fault while its new context is being programmed. */
    if (!a630_smmu_set(io,ctx,s,0xc00+4*s->slot,(s->s2cr&~0x30000u)|0x20000,0x30000) ||
        !a630_smmu_set(io,ctx,s,0x800+4*s->slot,s->smr&~(1u<<31),1u<<31)) goto done;
    for (unsigned n=0;n<A630_SMMU_IMPLS;n++)
        if (!s->foreign && !a630_smmu_set(io,ctx,s,a630_smmu_impl_offsets[n],a630_smmu_impl_values[n],UINT32_MAX)) goto done;
    s->stage=5;
    s->root=tables->physical|((uint64_t)s->bank<<48);
    if (!a630_smmu_set(io,ctx,s,s->context,0,1) ||
        !a630_smmu_set(io,ctx,s,s->page+0x800+4*s->bank,1,1) ||
        !a630_smmu_set(io,ctx,s,s->page+4*s->bank,0x1f300,0x3ffff) ||
        !a630_smmu_set64(io,ctx,s,s->context+0x20,s->root) ||
        !a630_smmu_set64(io,ctx,s,s->context+0x28,0) ||
        !a630_smmu_set(io,ctx,s,s->context+0x10,0x38001,UINT32_MAX) ||
        !a630_smmu_set(io,ctx,s,s->context+0x30,0x803519,UINT32_MAX) ||
        !a630_smmu_set(io,ctx,s,s->context+0x38,0xf404ff44,UINT32_MAX) ||
        !a630_smmu_set(io,ctx,s,s->context+0x3c,0,UINT32_MAX) ||
        !a630_smmu_tlb(io,ctx,s) ||
        !a630_smmu_set(io,ctx,s,s->context,0xc01127,0xc011ff)) goto done;
    s->stage=6;
    /* Reject unmatched streams, preserve every existing match. */
    if (!a630_smmu_set(io,ctx,s,0,(s->global|0x400u)&~1u,0x401) ||
        !a630_smmu_set(io,ctx,s,0x800+4*s->slot,(1u<<31)|A630_SMMU_STREAM,UINT32_MAX) ||
        !a630_smmu_set(io,ctx,s,0xc00+4*s->slot,
            (s->s2cr&~0x030303ffu)|0x300|s->bank,0x030303ff)) goto done;
    if (!io->sync(ctx)) {s->error=A630_SMMU_IO;goto done;}
    tables->dirty=0; s->stage=7;s->error=A630_SMMU_READY;
done:
    s->start_error=s->error;return (enum a630_smmu_error)s->error;
}
/* Only after all GMU/3D bus masters have stopped. If that cannot be
 * established, leave the pages resident and the power/clock lease held.
 * Cleanup has its own failure record and never erases the initial failure. */
static inline bool a630_smmu_end(const struct a630_smmu_io *io, void *ctx,
                               struct a630_smmu_snapshot *s)
{
    if (!s || !a630_smmu_callbacks(io)) return false;
    if (!s->changed) return true;
    struct a630_smmu_snapshot r=*s;
    r.error=0;r.failed_offset=0;r.expected=0;r.actual=0;r.polls=0;
    if (!a630_smmu_lease(io,ctx,&r)) goto failed;
    /* No more stream requests may enter the context during teardown. */
    if (!a630_smmu_set(io,ctx,&r,0xc00+4*s->slot,
            (s->s2cr&~0x30000u)|0x20000,0x30000) ||
        !a630_smmu_set(io,ctx,&r,0x800+4*s->slot,s->smr&~(1u<<31),UINT32_MAX) ||
        !a630_smmu_set(io,ctx,&r,s->context,0,1) ||
        !a630_smmu_tlb(io,ctx,&r)) goto failed;
    if (!a630_smmu_set64(io,ctx,&r,s->context+0x20,s->ttbr[0]) ||
        !a630_smmu_set64(io,ctx,&r,s->context+0x28,s->ttbr[1])) goto failed;
    for (unsigned n=1;n<5;n++)
        if (!a630_smmu_set(io,ctx,&r,s->context+a630_smmu_control[n],s->control[n],UINT32_MAX)) goto failed;
    if (!a630_smmu_set(io,ctx,&r,s->page+4*s->bank,s->cbar,0x3ffff) ||
        !a630_smmu_set(io,ctx,&r,s->page+0x800+4*s->bank,s->cba2r,1) ||
        !a630_smmu_set(io,ctx,&r,s->context,s->control[0],0xc011ff)) goto failed;
    if (!s->foreign) {
        for (unsigned n=0;n<A630_SMMU_IMPLS;n++)
            if (!a630_smmu_set(io,ctx,&r,a630_smmu_impl_offsets[n],s->impl[n],UINT32_MAX)) goto failed;
        uint32_t current;
        if (!a630_smmu_rd(io,ctx,&r,0,&current) ||
            !a630_smmu_set(io,ctx,&r,0,(current&~0x401u)|(s->global&0x401),0x401)) goto failed;
    }
    if (!a630_smmu_set(io,ctx,&r,0xc00+4*s->slot,s->s2cr,0x030303ff) ||
        !a630_smmu_set(io,ctx,&r,0x800+4*s->slot,s->smr,UINT32_MAX)) goto failed;
    if (!io->sync(ctx)) {r.error=A630_SMMU_IO;goto failed;}
    s->restored=1;s->restore_error=0;return true;
failed:
    s->restored=0;s->restore_error=r.error?r.error:A630_SMMU_RESTORE;
    return false;
}
#endif
