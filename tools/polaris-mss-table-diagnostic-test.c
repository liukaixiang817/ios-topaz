#include <stdint.h>
static uintptr_t table_base;
#define PGCD_TEST_TTBR0 (table_base|1)
struct pmni_translation;
static void table_at(struct pmni_translation*);
#define PMBN_TEST_AT_HOOK table_at
#define PMBN_TEST_ENTRY unused_boot_suite
#define PMRG_TEST_UNREGISTERED_MSS 1
#include "polaris-mss-boot-native-test.c"
static unsigned table_fault;
static void table_at(struct pmni_translation*t){if(t->page==0x4080000){t->read_par=t->write_par=0xb80;if(table_fault==3||table_fault==4){image_fault=table_fault==3?9:3;image_trigger=image_ats+1;}}}
int main(int argc,char**argv){
 aop_test_open(argc,argv);table_base=(uintptr_t)image_heap+0x80000;unsigned cases=0;
 for(unsigned fault=0;fault<8;fault++){
  table_base=(uintptr_t)image_heap+(fault==7?0x80000:0x60000);boot_setup();table_fault=fault;put((void*)table_base,table_base+4096+3,8);put((void*)(table_base+4096+0x20*8),table_base+8192+3,8);put((void*)(table_base+8192+0x80*8),0x703,8);
  if(fault==1)put((void*)table_base,0,8);if(fault==2)put((void*)table_base,table_base+3,8);
  if(fault==5)put((void*)(table_base+8192+0x80*8),0x4080703,8);
  if(fault==6)put((void*)(table_base+4096+0x20*8),3,8);
  CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));
  CHECK(!boot_drive()&&boot_owner->error==3&&!boot_calls);
  const struct pmbn_walk*w=&boot_owner->translation;CHECK(w->table.attempted&&!boot_records[0].native.issued);
  if(fault==0||fault==5){
   CHECK(w->table.complete&&w->table.stable&&w->table.levels==3&&w->table.physical==(fault==5?0x4080000u:0));
   for(unsigned pass=0;pass<2;pass++)for(unsigned n=0;n<3;n++)CHECK(w->source[pass][n].returned&&w->source[pass][n].bytes==8);
  }else if(fault==3||fault==4)CHECK(!w->table.complete&&w->table.error==2&&!w->source[0][0].returned&&!w->source[0][0].bytes);
  else if(fault==7)CHECK(!w->table.complete&&w->table.error==2&&w->read_error==2&&!w->source[0][0].issued);
  else CHECK(!w->table.complete&&w->table.error==(fault==2?6u:3u));
  unsigned old=image_ats;CHECK(pmbn_step(boot_owner)==PMBA_FAILED&&image_ats==old&&!boot_calls);cases++;
 }
 aop_test_close();printf("PASS %u native MBA table-diagnostic scenarios / %u checks; SOFTWARE only\n",cases,checks);return 0;
}
