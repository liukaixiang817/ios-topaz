/* New RAM-only discard/reuse integration. No storage/device interface. */
#include "polaris-ram-transaction.h"
#include "polaris-cow-arena.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned allocations,base_reads;
static void *ram(size_t n,void *v){allocations++;return polaris_arena_allocate(n,v);}
static int edge(void*v,uint64_t block,void*out){(void)v;(void)block;base_reads++;memset(out,0x44,4096);return 0;}
static int base(void*v,uint64_t block,uint32_t n,void*out){(void)v;(void)block;base_reads++;memset(out,0x44,n*4096);return 0;}
int main(void)
{
 struct polaris_cow*c=calloc(1,sizeof(*c));assert(c);c->nblocks=128;
 size_t reserved;assert(polaris_discard_reserve_bytes(c->nblocks,&reserved));
 size_t total=reserved+4*POLARIS_COW_BYTES;uint8_t*memory=calloc(1,total);assert(memory);
 struct polaris_ram_discard*d=(void*)memory;d->magic=POLARIS_TRIM_MAGIC;d->nblocks=c->nblocks;d->bitmap_bytes=(c->nblocks+7)/8;
 c->discard=d;c->limit=4;struct polaris_cow_arena a={memory+reserved,total-reserved,0};
 uint8_t input[8192],output[8192],bounce[8192];memset(input,0xa9,sizeof(input));
 assert(polaris_cow_put(c,0,2,input,ram,&a));assert(polaris_cow_put(c,4,1,input,ram,&a));
 struct polaris_ram_trim_extent trim={0,4096};
 assert(polaris_cow_discard(c,1,&trim));assert(c->dirty_blocks==2&&d->reusable==0&&d->zero_blocks==1);
 memset(output,0x44,sizeof(output));assert(polaris_cow_overlay(c,0,2,output));
 for(unsigned i=0;i<4096;i++)assert(!output[i]&&output[i+4096]==0xa9);
 trim.offset=4096;assert(polaris_cow_discard(c,1,&trim));assert(d->reusable==1&&polaris_cow_available(c)==3);
 unsigned before=allocations;
 assert(polaris_cow_put(c,8,1,input,ram,&a));assert(allocations==before&&d->reusable==0&&d->reused_groups==1);
 /* Every invalid batch leaves logical state and data untouched. */
 uint8_t saved_bits[16];memcpy(saved_bits,d->zeroes,16);uint64_t dirty=c->dirty_blocks,calls=d->calls;
 for(unsigned i=0;i<5;i++) {
  struct polaris_ram_trim_extent bad[2]={{16*4096,4096},{20*4096,4096}};
  if(i==0)bad[1].offset++;if(i==1)bad[1].length=0;if(i==2)bad[1].offset=128*4096;
  if(i==3)bad[1].offset=16*4096;if(i==4)bad[1].length=UINT64_MAX;
  assert(!polaris_cow_discard(c,2,bad)&&c->dirty_blocks==dirty&&d->calls==calls&&!memcmp(saved_bits,d->zeroes,16));
 }
 /* Trim read is a real RAM zero cache hit, not old immutable bytes. */
 memset(output,0xee,4096);memset(bounce,0xaa,4096);
 struct polaris_ram_request q={.logical=0,.physical=100,.blocks=1,.bytes=4096,.read=true,.data=output,.bounce=bounce};
 struct polaris_ram_result result=polaris_ram_io(c,&q,ram,&a,base,NULL);
 assert(result.status==POLARIS_RAM_OK&&!result.base_read&&base_reads==0);
 for(unsigned i=0;i<4096;i++)assert(!output[i]);
 /* 0907 partial-edge prepare must preserve trim-zero despite nonzero base. */
 struct polaris_ram_preparation prep=polaris_ram_prepare_write(c,0,5,3,bounce,ram,&a,edge,NULL,false);
 assert(prep.status==POLARIS_RAM_OK);
 uint8_t patch[3]={1,2,3};q=(struct polaris_ram_request){.logical=0,.physical=100,.blocks=1,.skip=5,.bytes=3,.data=patch,.bounce=bounce};
 result=polaris_ram_io(c,&q,ram,&a,base,NULL);assert(result.status==POLARIS_RAM_OK&&!polaris_discard_zero(d,0));
 memset(output,0x44,4096);assert(polaris_cow_overlay(c,0,1,output));
 for(unsigned i=0;i<4096;i++)assert(output[i]==(i>=5&&i<8?patch[i-5]:0));
 /* Reuse indefinitely across different virtual LBAs without growing arena. */
 for(unsigned n=0;n<1000;n++) {
  trim=(struct polaris_ram_trim_extent){0,c->nblocks*4096};assert(polaris_cow_discard(c,1,&trim));
  before=allocations;uint64_t block=(n%32)*4;assert(polaris_cow_put(c,block,1,input,ram,&a));
  assert(allocations==before&&a.used<=a.size&&c->used<=c->limit);
 }
 /* Corrupt/unknown chain rejects before changing any tombstone or data. */
 memcpy(saved_bits,d->zeroes,16);uint32_t head=c->buckets[0];c->buckets[0]=c->used+1;
 assert(!polaris_cow_discard(c,1,&trim)&&!memcmp(saved_bits,d->zeroes,16));c->buckets[0]=head;
 assert(polaris_discard_reserve_bytes(UINT64_C(16)*1024*1024*1024/4096,&reserved));
 assert(reserved<512*1024*1024&&reserved%16384==0);
 printf("PASS RAM discard/reuse/0907 partial-edge zero/invalid whole-batch; 1000 reuse cycles; 16GiB trim metadata=%zu within original512MiB\n",reserved);
 free(memory);free(c);
}
