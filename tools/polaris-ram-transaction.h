/* Whole-strategy RAM-COW write preparation. Caller holds the SAME mutex as
 * all reads/writes for preparation and every subsequent write fragment.
 * No persistent writer or storage command is exposed here. A base callback
 * may read exactly one immutable logical block into the existing bounce.
 * Reserve ALL groups before changing any request byte; materializing an
 * immutable partial edge in RAM is data-equivalent to the original base.
 * The strategy must split partial edge blocks from aligned full overwrites,
 * so its commit phase needs no base reads or further allocations.
 */
#ifndef POLARIS_RAM_TRANSACTION_H
#define POLARIS_RAM_TRANSACTION_H
#if defined(POLARIS_RAM_ONLY)
#include "polaris_ram_io.h"
#else
#include "polaris-ram-io.h"
#endif
/* 0909 may supply the same contract with empty-group reuse. Existing boards
 * retain this exact append-only implementation when that API is absent. */
#ifndef POLARIS_COW_REUSE_API
static inline unsigned polaris_cow_available(struct polaris_cow *c)
{return c&&c->used<=c->limit?c->limit-c->used:0;}
static inline struct polaris_cow_group *polaris_cow_ensure(struct polaris_cow *c,
    uint64_t number,polaris_cow_alloc allocate,void *allocator)
{
    struct polaris_cow_group *g=polaris_cow_find(c,number);
    if(g)return g;
    if(!polaris_cow_available(c))return NULL;
    uint8_t *data=allocate(POLARIS_COW_BYTES,allocator);if(!data)return NULL;
    g=&c->groups[c->used];g->number=number;g->data=data;g->valid=0;
    unsigned bucket=(unsigned)(number%POLARIS_COW_BUCKETS);
    g->next=c->buckets[bucket];c->buckets[bucket]=++c->used;return g;
}
#endif
struct polaris_ram_preparation {
    enum polaris_ram_status status;
    int base_error;
    uint64_t first,last;
    uint32_t groups_needed,base_reads,materialized_edges;
};
typedef int (*polaris_ram_read_edge_fn)(void *,uint64_t,void *);
static inline struct polaris_ram_preparation
polaris_ram_prepare_write(struct polaris_cow *c,uint64_t logical,
    uint32_t skip,uint32_t bytes,void *bounce,polaris_cow_alloc allocate,
    void *allocator,polaris_ram_read_edge_fn read_edge,void *reader,bool halted)
{
    struct polaris_ram_preparation out={POLARIS_RAM_INVALID,0,0,0,0,0,0};
    if(halted){out.status=POLARIS_RAM_STOPPED;return out;}
    if(!c||!bounce||!allocate||!read_edge||!bytes||skip>=POLARIS_COW_BLOCK||
       !c->limit||c->limit>POLARIS_COW_GROUPS||c->used>c->limit||
       !c->nblocks||c->nblocks>(UINT64_C(64)<<18)||logical>=c->nblocks)return out;
    uint64_t blocks=((uint64_t)skip+bytes+POLARIS_COW_BLOCK-1)/POLARIS_COW_BLOCK;
    if(blocks>c->nblocks-logical)return out;
    out.first=logical/4;out.last=(logical+blocks-1)/4;
    if(out.last-out.first+1>c->limit){out.status=POLARIS_RAM_FULL;return out;}
    for(uint64_t n=out.first;n<=out.last;n++)if(!polaris_cow_find(c,n))out.groups_needed++;
    if(out.groups_needed>polaris_cow_available(c)){out.status=POLARIS_RAM_FULL;return out;}
    /* Allocation failure leaves only empty groups, never partial request data.
     * The wired arena used on the phone cannot fail after this budget check,
     * but keep generic allocator failure observable instead of assuming it. */
    for(uint64_t n=out.first;n<=out.last;n++)
        if(!polaris_cow_ensure(c,n,allocate,allocator)) {
            out.status=POLARIS_RAM_FULL;return out;
        }
    uint64_t edge[2]={logical,logical+blocks-1};
    bool partial[2]={skip!=0,((uint64_t)skip+bytes)%POLARIS_COW_BLOCK!=0};
    for(unsigned n=0;n<2;n++) {
        if(!partial[n]||(n&&edge[n]==edge[0]&&partial[0]))continue;
        struct polaris_cow_group *g=polaris_cow_find(c,edge[n]/4);
        unsigned slot=(unsigned)(edge[n]%4);
        if(g->valid&(1u<<slot))continue;
        out.base_reads++;
        out.base_error=read_edge(reader,edge[n],bounce);
        if(out.base_error){out.status=POLARIS_RAM_BASE_ERROR;return out;}
        /* 0909 zero tombstones must override immutable data before an edge
         * is materialized, so a partial write cannot resurrect discarded data. */
        if(!polaris_cow_overlay(c,edge[n],1,bounce))return out;
        __builtin_memcpy(g->data+slot*POLARIS_COW_BLOCK,bounce,POLARIS_COW_BLOCK);
        g->valid|=(uint8_t)(1u<<slot);c->dirty_blocks++;out.materialized_edges++;
    }
    out.status=POLARIS_RAM_OK;return out;
}
#endif
