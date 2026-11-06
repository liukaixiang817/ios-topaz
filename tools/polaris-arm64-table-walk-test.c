#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-arm64-table-walk.h"
static unsigned calls,fail_call,change_call;
static uint64_t desc[4],entries[4];
static int reader(void*context,unsigned pass,unsigned index,uint64_t at,uint64_t*v)
{assert(!context&&pass<2&&index<4);calls++;if(calls==fail_call)return 0;assert(at==entries[index]);*v=desc[index]^(calls==change_call?4:0);return 1;}
static unsigned cases;
static void setup(void){calls=fail_call=change_call=0;memset(desc,0,sizeof(desc));memset(entries,0,sizeof(entries));}
static struct pmpt_walk walk(uint64_t ttbr,uint64_t tcr,uint64_t va){struct pmpt_walk w={0};(void)pmpt_collect(&w,ttbr,tcr,va,reader,0);cases++;return w;}
int main(void){
 /* VA04080000, 32-bit VA/4KiB tables: L1,L2,L3; leaf PA zero is evidence. */
 for(unsigned target=0;target<2;target++){
  setup();entries[0]=0x100000;entries[1]=0x101000+0x20*8;entries[2]=0x102000+0x80*8;
  desc[0]=0x101003;desc[1]=0x102003;desc[2]=target?0x4080703:0x703;
  struct pmpt_walk w=walk(0x100001,0x80803520,0x4080000);assert(w.complete&&w.stable&&!w.error&&w.first==1&&w.leaf==3&&w.levels==3&&calls==6&&w.physical==(target?0x4080000:0));
  for(unsigned fail=1;fail<=6;fail++){calls=0;fail_call=fail;w=walk(0x100001,0x80803520,0x4080000);assert(!w.complete&&w.error==2&&calls==fail);}fail_call=0;
  for(unsigned change=4;change<=6;change++){calls=0;change_call=change;w=walk(0x100001,0x80803520,0x4080000);assert(!w.complete&&w.error==4&&calls==change);}change_call=0;
 }
 /* L1 and L2 blocks retain VA offset in decoded PA. */
 setup();entries[0]=0x100000;desc[0]=0x701;struct pmpt_walk w=walk(0x100000,32,0x4080000);assert(w.complete&&w.physical==0x4080000&&w.levels==1&&calls==2);
 setup();entries[0]=0x100000;entries[1]=0x101000+0x20*8;desc[0]=0x101003;desc[1]=0x50000701;w=walk(0x100000,32,0x4080000);assert(w.complete&&w.physical==0x50080000&&w.levels==2&&calls==4);
 for(unsigned fault=0;fault<9;fault++){
  setup();uint64_t ttbr=0x100000,tcr=32,va=0x4080000;
  if(fault==0)tcr=15;if(fault==1)tcr=40;if(fault==2)tcr|=1u<<14;if(fault==3)tcr|=128;if(fault==4)tcr|=UINT64_C(1)<<59;if(fault==5)tcr|=UINT64_C(6)<<32;if(fault==6)va=UINT64_C(1)<<32;if(fault==7)ttbr|=2;if(fault==8)ttbr=0;
  w=walk(ttbr,tcr,va);assert(w.error==1&&!calls&&!w.complete);
 }
 for(unsigned fault=0;fault<5;fault++){
  setup();entries[0]=0x100000;desc[0]=fault==0?0:fault==1?2:fault==2?0x1701:fault==3?3:UINT64_C(0x0001000000000701);
  w=walk(0x100000,32,0x4080000);assert(w.error==3&&!w.complete&&w.stable&&calls==2);
 }
 setup();entries[0]=0x100000;desc[0]=0x100003;w=walk(0x100000,32,0x4080000);assert(w.error==6&&calls==1);
 /* Four-level root, and shortest supported three-level-free 25-bit input. */
 setup();for(unsigned n=0;n<4;n++){entries[n]=0x100000+4096*n;desc[n]=0x101003+4096*n;}desc[3]=0x703;
 w=walk(0x100000,16,0);assert(w.complete&&w.first==0&&w.levels==4&&w.leaf==3&&calls==8);
 setup();entries[0]=0x100000;desc[0]=0x701;w=walk(0x100000,39,0);assert(w.complete&&w.first==2&&calls==2);
 struct pmpt_walk before=w;assert(!pmpt_collect(&w,0x100000,39,0,reader,0)&&!memcmp(&w,&before,sizeof(w)));
 printf("PASS %u read-only page-table decode/bounds/stability scenarios; SOFTWARE only\n",cases);return 0;
}
