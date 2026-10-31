/* SOFTWARE services only: neither numeric resource ranges nor SMC are accessed. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
static void text(const char *s){(void)s;}
static void report(const char *s,uint64_t v){(void)s;(void)v;}
#include "uefi-wifi-resources-readonly.h"
struct allocation {struct pfr_result result;struct pfr_lifetime ticket;};
static struct allocation *storage;
static struct pfr_result *result;
static struct pwfc_result witness;
static struct efi_boot boot;
static struct efi_system fw_system;
static uint8_t captured[632];
static unsigned fault,map_calls,aff_calls,arch_calls,orders,completion_barriers;
static uint64_t now;
static jmp_buf escape;
static struct efi_memory descriptor(uint32_t type,uint64_t start,uint64_t bytes)
{return (struct efi_memory){.type=type,.physical=start,.pages=bytes/4096,.attributes=1};}
static efi_status get_map(uint64_t *bytes,void *buffer,uint64_t *key,uint64_t *stride,uint32_t *version)
{
 unsigned n=map_calls++;assert(n<2&&*bytes==PFR_MAP_CAP&&result->map[n].issued==1&&result->map[n].completed==0);
 assert(result->error==PFR_OUTSTANDING&&orders);
 if(fault==18)longjmp(escape,1);
 uint8_t raw[8*48]={0};
 for(unsigned k=0;k<6;k++){struct efi_memory d=descriptor(fault==23?7:0,pfr_ranges[k].start,pfr_ranges[k].bytes);memcpy(raw+k*48,&d,40);}
 uint64_t base=(uintptr_t)storage,owned_bytes=32768;
 struct efi_memory own=descriptor(fault==7?0:4,base,owned_bytes);memcpy(raw+6*48,&own,40);
 struct efi_memory extra=descriptor(3,0x100000,4096);memcpy(raw+7*48,&extra,40);
 *key=101;*stride=48;*version=1;*bytes=sizeof(raw);
 if(fault==1){*bytes=PFR_MAP_CAP+48;return EFI_TOO_SMALL;}
 if(fault==2)*stride=39;
 if(fault==3)*version=2;
 if(fault==4){struct efi_memory d=descriptor(0,0x8e400000,4096);memcpy(raw+7*48,&d,40);}
 if(fault==5&&n)*key=102;
 if(fault==6&&n)raw[47]=1;
 if(fault==8&&n){memset(buffer,0x5a,17);return EFI_ERROR|7;}
 if(fault==21){struct efi_memory d=descriptor(0,0x8e400000+4096,0x7800000-4096);memcpy(raw,&d,40);}
 if(fault==22){struct efi_memory d=descriptor(64,0x8e400000,0x7800000);d.attributes=UINT64_C(0x8000000000000001);memcpy(raw,&d,40);}
 if(fault==24)*key=0;
 memcpy(buffer,raw,sizeof(raw));return 0;
}
static int arch(void *ctx,struct pwfc_arch *a)
{
 (void)ctx;arch_calls++;*a=witness.after;a->ticks=++now;
 if(fault==9)a->ticks=witness.after.ticks+PFR_BUDGET_TICKS+1;
 if(fault==10)a->mair=0xffbb0000;
 if(fault==11&&aff_calls==3)a->ticks=witness.after.ticks;
 if(fault==12&&aff_calls==4)a->ttbr0++;
 if(fault==19&&aff_calls==3)return 0;
 return 1;
}
static int64_t affinity(void *ctx,uint64_t target)
{
 (void)ctx;unsigned n=aff_calls++;assert(n<7&&target==pfr_peers[n]);
 assert(result->affinity_issued&(1u<<n));assert(!(result->affinity_completed&(1u<<n)));
 assert(result->affinity_unknown&(1u<<n));assert(result->error==PFR_OUTSTANDING&&orders);
 if(fault==20&&n==2)longjmp(escape,1);
 if(n==2){if(fault==13)return 0;if(fault==14)return 2;if(fault==15)return -1;if(fault==16)return 7;}
 return 1;
}
static void order(void *ctx)
{
 (void)ctx;orders++;
 for(unsigned n=0;n<7;n++)if((result->affinity_completed&(1u<<n))&&(result->affinity_unknown&(1u<<n)))completion_barriers++;
}
static void reset(void)
{
 memset(storage,0,32768);result=&storage->result;memset(&witness,0,sizeof(witness));
 map_calls=aff_calls=arch_calls=orders=completion_barriers=0;
 boot=(struct efi_boot){.get_map=get_map};fw_system=(struct efi_system){.boot=&boot};
 witness.attempted=1;witness.owner_matches=1;witness.hash_count=4;
 witness.image=pwfi_le(captured+32,8)-0x5cb0;witness.protocol=witness.image+0x7090;
 witness.protocol_after=witness.protocol;witness.release_attempted=1;
 witness.cache_consistent=1;witness.mpss_cached=1;witness.map_key[0]=witness.map_key[1]=0x108e;
 witness.snapshot_bytes[0]=witness.snapshot_bytes[1]=632;
 memcpy(witness.snapshot[0],captured,632);memcpy(witness.snapshot[1],captured,632);
 for(unsigned n=0;n<4;n++)memcpy(witness.hashes[n],pwfi_ranges[n].sha256,32);
 witness.owner=(struct efi_loaded){.revision=0x1000,.base=(void*)(uintptr_t)witness.image,.bytes=PWFI_IMAGE_BYTES,.system=&fw_system,.code_type=3,.data_type=4};
 witness.smem_descriptor=(struct efi_memory){.physical=0x86000000,.pages=512,.type=0,.attributes=1};witness.smem_descriptor_matches=1;
 witness.before=(struct pwfc_arch){.el=4,.mpidr=0x81000000,.ttbr0=0x13ffe8000,.tcr=0x280803518,.sctlr=0xc0180d,.mair=0xffbb4400,.sre=1,.group1=1,.frequency=19200000,.ticks=10000000};
 witness.after=witness.before;witness.after.ticks+=53570;witness.cookie=witness.before.ticks|1;now=witness.after.ticks;
 struct efi_loaded self={.revision=0x1000,.base=storage,.bytes=32768,.system=&fw_system,.code_type=3,.data_type=4};assert(pfr_bind(result,&self));assert(!pfr_bind(result,&self));
}
static int run(unsigned enabled,unsigned stage)
{const struct pfr_io io={0,&fw_system,arch,affinity,order};return pfr_collect(enabled,stage,&witness,&io,&storage->ticket,result);}
int main(int argc,char **argv)
{
 assert(argc==2&&sizeof(*storage)<=32768);FILE *f=fopen(argv[1],"rb");assert(f&&fread(captured,1,632,f)==632&&!fclose(f));
 assert(!posix_memalign((void**)&storage,4096,32768));unsigned checks=0;reset();
 assert(run(1,2)&&result->error==0&&result->phase==4&&map_calls==2&&aff_calls==7&&result->affinity_issued==127&&result->affinity_completed==127&&!result->affinity_unknown&&result->all7_observed_OFF&&result->maps_byteidentical&&completion_barriers==7);checks++;
 for(unsigned m=0;m<2;m++)for(unsigned k=0;k<6;k++)assert(result->coverage[m][k].complete&&result->coverage[m][k].type_mask==1);checks++;
 assert(!run(1,2)&&map_calls==2&&aff_calls==7);checks++;
 struct pfr_result fresh={0};const struct pfr_io io={0,&fw_system,arch,affinity,order};assert(!pfr_collect(1,2,&witness,&io,&storage->ticket,&fresh)&&!fresh.attempted);checks++;
 reset();assert(!run(0,2)&&result->error==PFR_DISABLED&&!map_calls&&!aff_calls&&!arch_calls);checks++;
 reset();assert(!run(1,4)&&result->error==PFR_STAGE&&!map_calls&&!aff_calls&&!arch_calls);checks++;
 reset();witness.hashes[0][0]^=1;assert(!run(1,2)&&result->error==PFR_WITNESS&&!map_calls&&!aff_calls&&!arch_calls);checks++;
 reset();witness.owner.system=0;assert(!run(1,2)&&result->error==PFR_WITNESS&&!map_calls&&!aff_calls&&!arch_calls);checks++;
 for(unsigned n=1;n<=24;n++){
  fault=n;reset();if(n==17)result->self_bound=0;int ok=0;if(!setjmp(escape))ok=run(1,2);
  if(n==21||n==22||n==23){assert(ok&&result->maps_byteidentical&&map_calls==2&&aff_calls==7);
    if(n==21)assert(!result->coverage[0][0].complete&&result->coverage[0][0].covered_bytes==0x7800000-4096);
    if(n==22)assert(result->coverage[0][0].unknown_type&&result->coverage[0][0].runtime_seen&&!result->coverage[0][0].type_mask);
    if(n==23)assert(result->coverage[0][0].type_mask==(1u<<7));
  }else{assert(!ok&&result->error&&map_calls<=2&&aff_calls<=7);
    if(n==1)assert(result->error==PFR_MAP_STATUS&&result->map[0].bytes>PFR_MAP_CAP&&!aff_calls);
    if(n==2||n==3||n==4||n==24)assert(result->error==PFR_MAP_GEOMETRY&&!aff_calls);
    if(n==5||n==6)assert(result->error==PFR_MAP_CHANGED&&!result->maps_byteidentical&&map_calls==2&&aff_calls==7);
    if(n==7)assert(result->error==PFR_SELF&&!aff_calls);
    if(n==8)assert(result->error==PFR_MAP_STATUS&&result->maps[1][0]==0x5a&&result->maps[1][16]==0x5a&&result->maps[1][17]==0);
    if(n==9||n==11)assert(result->error==PFR_CLOCK);
    if(n==10||n==12||n==19)assert(result->error==PFR_ARCH);
    if(n==11||n==19)assert(aff_calls==3&&!result->all7_observed_OFF&&result->affinity_completed==7);
    if(n==12)assert(aff_calls==4&&!result->all7_observed_OFF);
    if(n>=13&&n<=16){assert(aff_calls==7&&map_calls==2&&result->affinity_completed==127&&!result->all7_observed_OFF&&result->affinity_raw[6]==1);if(n==15)assert(result->affinity_raw[2]==UINT64_MAX);}
    if(n==17)assert(result->error==PFR_SELF&&!arch_calls&&!map_calls&&!aff_calls);
    if(n==18)assert(result->error==PFR_OUTSTANDING&&result->map[0].issued&&!result->map[0].completed&&!aff_calls);
    if(n==20)assert(result->error==PFR_OUTSTANDING&&aff_calls==3&&result->affinity_issued==7&&result->affinity_completed==3&&result->affinity_unknown==4&&!result->all7_observed_OFF);
  }
  unsigned m=map_calls,a=aff_calls;assert(!run(1,2)&&m==map_calls&&a==aff_calls);checks++;
 }
 free(storage);printf("{\"checks\":%u,\"result_bytes\":%zu,\"maps_offset\":%zu,\"maximum_GetMemoryMap_calls\":2,\"maximum_AFFINITY_INFO_calls\":7,\"all_OFF_is_observation_only\":true,\"physical_executed\":false,\"resource_writes\":false}\n",checks,sizeof(struct pfr_result),offsetof(struct pfr_result,maps));return 0;
}
