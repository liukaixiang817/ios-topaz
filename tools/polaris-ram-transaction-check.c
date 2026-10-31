/* Real COW/RAM-IO/transaction code against an independent byte-array disk.
 * SOFTWARE regression only: no device, HFS repair or persistent writes. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "polaris-ram-transaction.h"
#define TBLOCKS 32u
#define TBYTES (TBLOCKS*POLARIS_COW_BLOCK)
static uint8_t immutable[TBYTES],expect[TBYTES],input[TBYTES],bounce[TBYTES];
static int allocations=-1,edge_error_at=-1;static unsigned edge_calls,base_calls;
static void *alloc_ram(size_t bytes,void *context)
{
    (void)context;if(!allocations)return NULL;if(allocations>0)allocations--;
    return calloc(1,bytes);
}
static int base_read(void *context,uint64_t block,uint32_t count,void *out)
{
    (void)context;base_calls++;assert(block+count<=TBLOCKS);
    memcpy(out,immutable+block*4096,count*4096);return 0;
}
static int edge_read(void *context,uint64_t block,void *out)
{
    (void)context;unsigned index=edge_calls++;
    if((int)index==edge_error_at)return 5;
    assert(block<TBLOCKS);memcpy(out,immutable+block*4096,4096);return 0;
}
static void reset(struct polaris_cow *c,unsigned limit)
{
    for(unsigned n=0;n<c->used;n++)free(c->groups[n].data);
    memset(c,0,sizeof(*c));c->limit=limit;c->nblocks=TBLOCKS;
    allocations=-1;edge_error_at=-1;edge_calls=base_calls=0;
    memcpy(expect,immutable,sizeof(expect));
}
static void actual(struct polaris_cow *c,uint8_t *out)
{memcpy(out,immutable,TBYTES);assert(polaris_cow_overlay(c,0,TBLOCKS,out));}
/* Match the driver's new fragment split, plus artificial outer extent ends
 * every4 blocks to expose the old partial-write failure on a two-block node. */
static enum polaris_ram_status commit(struct polaris_cow *c,uint64_t off,
    uint32_t bytes,bool prepared)
{
    uint32_t done=0;
    while(done<bytes) {
        uint64_t pos=off+done,block=pos/4096;uint32_t skip=(uint32_t)(pos%4096);
        uint32_t want=bytes-done;if(want>12288-skip)want=12288-skip;
        if(prepared) {
            if(skip&&want>4096-skip)want=4096-skip;
            else if(!skip&&want>4096&&want%4096)want-=want%4096;
        }
        uint32_t blocks=(skip+want+4095)/4096;
        unsigned extent=4-(unsigned)(block%4);if(blocks>extent)blocks=extent;
        if(want>blocks*4096-skip)want=blocks*4096-skip;
        struct polaris_ram_request q={.logical=block,.physical=block,.blocks=blocks,
            .skip=skip,.bytes=want,.read=false,.data=input+done,.bounce=bounce};
        struct polaris_ram_result result=polaris_ram_io(c,&q,alloc_ram,NULL,base_read,NULL);
        if(result.status!=POLARIS_RAM_OK)return result.status;
        done+=want;
    }
    return POLARIS_RAM_OK;
}
int main(void)
{
    struct polaris_cow *c=calloc(1,sizeof(*c));uint8_t *got=malloc(TBYTES);
    assert(c&&got);for(unsigned n=0;n<TBYTES;n++)immutable[n]=(uint8_t)(n*37u+(n>>12));
    memset(input,0x76,sizeof(input));
    /* Proven defect: old split strategy commits a first 4K fragment before
     * the next fragment discovers ENOSPC. Native HFS node size here is8K. */
    reset(c,1);assert(commit(c,3*4096,8192,false)==POLARIS_RAM_FULL);
    actual(c,got);assert(memcmp(got,immutable,TBYTES));
    assert(!memcmp(got+3*4096,input,4096)&&!memcmp(got+4*4096,immutable+4*4096,4096));
    /* Whole-request budget failure changes zero request bytes, including an
     * already-dirty first group that could otherwise accept its prefix. */
    reset(c,1);assert(polaris_cow_put(c,3,1,immutable+3*4096,alloc_ram,NULL));
    struct polaris_ram_preparation p=polaris_ram_prepare_write(c,3,0,8192,bounce,
        alloc_ram,NULL,edge_read,NULL,false);
    assert(p.status==POLARIS_RAM_FULL&&edge_calls==0);actual(c,got);
    assert(!memcmp(got,immutable,TBYTES));
    /* Two boundary reads happen before commit; no base I/O or allocation is
     * needed during any commit fragment across extent and bounce boundaries. */
    reset(c,8);p=polaris_ram_prepare_write(c,1,17,60001,bounce,alloc_ram,NULL,edge_read,NULL,false);
    assert(p.status==POLARIS_RAM_OK&&edge_calls==2);unsigned used=c->used;
    allocations=0;assert(commit(c,4096+17,60001,true)==POLARIS_RAM_OK&&base_calls==0&&c->used==used);
    memcpy(expect+4096+17,input,60001);actual(c,got);assert(!memcmp(got,expect,TBYTES));
    reset(c,8);allocations=1;p=polaris_ram_prepare_write(c,3,0,8192,bounce,alloc_ram,NULL,edge_read,NULL,false);
    assert(p.status==POLARIS_RAM_FULL&&c->used==1&&!c->groups[0].valid);actual(c,got);
    assert(!memcmp(got,immutable,TBYTES));
    reset(c,8);edge_error_at=1;p=polaris_ram_prepare_write(c,1,17,16001,bounce,alloc_ram,NULL,edge_read,NULL,false);
    assert(p.status==POLARIS_RAM_BASE_ERROR&&p.base_error==5&&edge_calls==2);
    actual(c,got);assert(!memcmp(got,immutable,TBYTES)); /* first materialized edge equals base */
    reset(c,8);p=polaris_ram_prepare_write(c,1,17,19,bounce,alloc_ram,NULL,edge_read,NULL,false);
    assert(p.status==POLARIS_RAM_OK&&edge_calls==1);
    allocations=0;assert(commit(c,4096+17,19,true)==POLARIS_RAM_OK&&base_calls==0);
    reset(c,8);p=polaris_ram_prepare_write(c,1,0,4096,bounce,alloc_ram,NULL,edge_read,NULL,true);
    assert(p.status==POLARIS_RAM_STOPPED&&c->used==0&&edge_calls==0);
    p=polaris_ram_prepare_write(c,TBLOCKS-1,4095,2,bounce,alloc_ram,NULL,edge_read,NULL,false);
    assert(p.status==POLARIS_RAM_INVALID&&c->used==0&&edge_calls==0);
    reset(c,8);for(unsigned n=0;n<16;n++) {
        unsigned skip=(n*379)%4096,bytes=1+n*997;
        reset(c,8);p=polaris_ram_prepare_write(c,1,skip,bytes,bounce,alloc_ram,NULL,edge_read,NULL,false);
        assert(p.status==POLARIS_RAM_OK);allocations=0;
        assert(commit(c,4096+skip,bytes,true)==POLARIS_RAM_OK&&base_calls==0);
        memcpy(expect+4096+skip,input,bytes);actual(c,got);assert(!memcmp(got,expect,TBYTES));
    }
    for(unsigned n=0;n<TBYTES;n++)assert(immutable[n]==(uint8_t)(n*37u+(n>>12)));
    reset(c,8);free(c);free(got);
    puts("PASS: old8K split-ENOSPC defect reproduced; 24 whole-write/partial-edge/failure checks; immutable base unchanged");
    return 0;
}
