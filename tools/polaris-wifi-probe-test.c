/* Physical-read callback simulation; this program performs no physical I/O. */
#include "polaris-wifi-smem-probe.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static uint8_t memory[PWF_SMEM_BYTES], baseline[PWF_SMEM_BYTES];
static struct polaris_wifi_probe_workspace work;
static uint32_t calls, translations, deny, wrong_page, remap_page, mutation, forbidden;
static bool live_now;
static const uint32_t part=20480, span=32768, toc=PWF_SMEM_BYTES-4096, desc=20480+48;
static const uintptr_t VBASE=0x400000;
static void put(uint32_t at,uint32_t v){for(unsigned i=0;i<4;i++)memory[at+i]=(uint8_t)(v>>(8*i));}
static void partition(uint32_t i,uint32_t at,uint32_t n,uint32_t hosts)
{
 uint32_t t=toc+32+48*i;put(t,at);put(t+4,n);put(t+12,hosts);put(t+16,64);
 put(at,0x54525024);put(at+4,hosts);put(at+8,n);put(at+12,32);put(at+16,n);
}
static void entry(uint32_t at,uint32_t id,uint32_t n,uint32_t hp)
{put(at,0xa5a5|(id<<16));put(at+4,n);put(at+8,hp<<16);}
static void setup(void)
{
 memset(memory,0,sizeof(memory));calls=translations=deny=wrong_page=remap_page=mutation=forbidden=0;live_now=true;
 put(92,0xc0000);put(192,1);put(toc,0x434f5424);put(toc+4,1);put(toc+8,3);
 partition(0,12288,4096,0xfffefffe);partition(1,part,span,0x00010000);
 partition(2,57344,2048,0x00030001); /* another-host header must not be read */
 entry(part+32,478,32,0);entry(part+80,479,256,0);put(part+12,352);
 entry(part+span-64,480,512,48);put(part+16,span-576);
 put(desc,8);put(desc+4,8);put(desc+8,16);put(desc+12,16);
 memset(memory+part+96,0x6b,256);memset(memory+part+span-576,0x7c,512);
}
static bool live(void *ctx,uint64_t epoch){return ctx==memory&&epoch==37&&live_now;}
static bool order(void *ctx){return ctx==memory;}
static bool translate(void *ctx,uintptr_t va,uint64_t *pa,uint64_t *par)
{
 assert(ctx==memory&&va>=VBASE&&va-VBASE<PWF_SMEM_BYTES);translations++;
 uint32_t page=(uint32_t)(va-VBASE)/4096;
 *pa=PWF_SMEM_PHYSICAL+page*4096;*par=*pa;
 if(wrong_page&&page==wrong_page-1)*pa+=4096;
 if(remap_page&&translations>PWF_SMEM_PAGES&&page==remap_page-1)*par^=0x80;
 return true;
}
static bool read_only(void *ctx,uintptr_t va,void *dst,size_t n)
{
 assert(ctx==memory&&va>=VBASE&&va-VBASE<PWF_SMEM_BYTES);calls++;
 uint32_t at=(uint32_t)(va-VBASE);
 bool allowed=(at==0&&n==208)||(at>=toc&&n<=PWF_SMEM_BYTES-at)||
  ((at==12288||at==part||at==desc)&&n==32)||
  ((at==part+32||at==part+80||at==part+span-64)&&n==16);
 if(!allowed){forbidden++;return false;}
 if(calls==deny)return false;
 memcpy(dst,memory+at,n);
 if(mutation&&at==desc){memory[desc+4]^=8;mutation=0;}
 return true;
}
int main(void)
{
 struct polaris_wifi_probe_io io={memory,VBASE,37,live,translate,read_only,order};
 struct polaris_wifi_probe_result r;
 setup();memcpy(baseline,memory,sizeof(memory));
 assert(polaris_wifi_smem_probe(&io,1,&r,&work));
 assert(r.pages==512&&translations==1024&&r.metadata_stable&&r.descriptor_stable&&r.queues_empty);
 assert(!r.mpu_verified&&!r.exclusive_owner_verified&&!r.may_transmit&&!forbidden);
 assert(!memcmp(baseline,memory,sizeof(memory)));
 uint32_t n=calls;
 for(uint32_t i=1;i<=n;i++) {
  setup();deny=i;assert(!polaris_wifi_smem_probe(&io,1,&r,&work)&&r.error&&!r.may_transmit);
  assert(!memcmp(baseline,memory,sizeof(memory))&&!forbidden);
 }
 setup();wrong_page=33;assert(!polaris_wifi_smem_probe(&io,1,&r,&work)&&r.error==4&&!calls);
 setup();remap_page=100;assert(!polaris_wifi_smem_probe(&io,1,&r,&work)&&r.error==4&&!r.may_transmit);
 setup();mutation=1;assert(!polaris_wifi_smem_probe(&io,1,&r,&work)&&r.error==6);
 setup();live_now=false;assert(!polaris_wifi_smem_probe(&io,1,&r,&work)&&!calls);
 setup();put(desc+12,24);assert(polaris_wifi_smem_probe(&io,1,&r,&work)&&!r.queues_empty&&!r.may_transmit);
 setup();put(desc+12,3);assert(!polaris_wifi_smem_probe(&io,1,&r,&work)&&r.error==7);
 printf("PASS software RO probe: 512 actual-translation callbacks before/after, %u denied-read stages, no FIFO/other-host/SMEM write; transmit always false\n",n);
}
