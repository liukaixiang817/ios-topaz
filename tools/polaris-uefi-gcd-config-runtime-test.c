#define main legacy_main
#include "polaris-uefi-gcd-test.c"
#undef main
/* NEW RuntimeData exactspan SOFTWARE cases; no original code/MMIO/SMEM. */
static unsigned scenario,config_AT;
static int rtmap(void *opaque,struct efi_system *sys,struct pgcd_map *m,void *out){
 (void)opaque;assert(sys==s);maps++;assert(m->issued&&r->outstanding);
 unsigned cross=scenario==2||scenario==7||scenario==8||scenario==9;
 uint64_t start=(uintptr_t)arena+0x4c000,stop=start+(cross?8192:4096);
 struct efi_memory d[4]={{3,0,(uintptr_t)arena,0,0x4c000/4096,8},
 {scenario==5?5:scenario==6?7:scenario==12?4:6,0,start,0,(stop-start)/4096,scenario==3?15:scenario==4?0x8000000000000008ULL:scenario==12?15:0x800000000000000fULL},
 {3,0,stop,0,((uintptr_t)arena+0x100000-stop)/4096,8},{0}};
 unsigned n=3;
 if(scenario==7){d[1].pages=1;d[2].physical=start+4096;d[2].pages=((uintptr_t)arena+0x100000-d[2].physical)/4096;}
 if(scenario==8){d[3]=d[2];d[1].pages=1;d[2]=(struct efi_memory){6,0,start+4096,0,1,0x800000000000000fULL};n=4;}
 memcpy(out,d,n*sizeof(d[0]));m->status=0;m->bytes=n*sizeof(d[0]);m->key=1;m->stride=sizeof(d[0]);m->version=1;return 1;
}
static int rtid(void *opaque,uint64_t at,uint64_t n,uint64_t *where,uint64_t *par){
 if(at>=(uintptr_t)arena+0x4c000&&at<(uintptr_t)arena+0x4e000){
  config_AT++;assert(n==4096&&r->outstanding);*where=at;*par=0xff00000000000b80ULL|at;
  if(scenario==9&&config_AT==2)*par=0x4400000000000a00ULL|at;
  if(scenario==10){*par=at|1;return 0;}
  if(scenario==11)s->table_count=2;
  return 1;
 }
 return identity(opaque,at,n,where,par);
}
int main(int argc,char **argv){
 assert(!legacy_main(argc,argv));assert(!posix_memalign((void**)&arena,4096,0x101000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
 FILE *f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));unsigned tests=0;
 for(unsigned k=1;k<=15;k++){
  reset(0);scenario=k;config_AT=0;c->io.map=rtmap;c->io.identity=rtid;
  if(k==2||k==7||k==8||k==9){struct pgcd_config saved=cfg[0];cfg=(void*)(arena+0x4cff0);cfg[0]=saved;cfg[1]=(struct pgcd_config){0};s->tables=cfg;s->table_count=2;}
  if(k==13){self->bytes=r->self_owner.bytes=r->self_bytes=0x4d000;}
  if(k==14)s->table_count=129;
  if(k==15)s->tables=(void*)(uintptr_t)(UINT64_MAX-15);
  int ok=all();
  if(k==1||k==2||k==12){assert(ok&&queries==8&&!pgcd_uncertain(c)&&r->config_span[0].admission_class==(k==12?1u:2u));assert(r->config_span[1].completed==(k==2?3u:1u));assert(config_AT==(k==2?4u:2u));}
  else {assert(!ok&&!queries);if(k==3||k==4||k==5||k==6)assert(r->config_span[0].error==6&&!config_AT);if(k==7||k==8)assert(r->config_span[0].error==5&&!config_AT);if(k==9)assert(r->config_span[0].error==9&&r->config_span[0].issued==3&&r->config_span[0].completed==3);if(k==10)assert(r->config_span[0].error==8&&r->config_span[0].completed==1);if(k==11)assert(r->config_span[0].error==4&&pgcd_uncertain(c));if(k==13)assert(r->config_span[0].error==3&&!config_AT);if(k==14||k==15)assert(!config_AT);}
  tests++;
 }
 free(original);free(arena);printf("{\"NEW_exactspan_tests\":%u,\"legacy_affected_regression_cases\":36,\"new_GCD_bytes\":%zu,\"config_span_bytes\":%zu,\"guard_bytes\":%zu,\"observation_bytes\":%zu,\"original_firmware_executed\":false}\n",tests,sizeof(struct pgcd_result),sizeof(struct pgcd_config_span),sizeof(struct pgcd_service_guard),sizeof(struct pgcd_observation));return 0;
}
