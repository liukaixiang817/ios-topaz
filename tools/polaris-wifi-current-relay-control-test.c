/* Existing active relay callbacks, SOFTWARE leaves and genuine generic
 * contexts only. Original PE and captured retired pointers are DATA only. */
#define _DARWIN_C_SOURCE 1
#define POLARIS_CURRENT_MAP_DISPATCH_FIXTURE_ONLY 1
#include "polaris-wifi-current-map-dispatch-test.c"
#include <setjmp.h>
#include <sys/mman.h>
static unsigned relay_point,relay_mode,relay_byte,relay_route,relay_slot,relay_hit;
static struct pcmp_live relay_before,relay_after;
static struct pcmp_input relay_alias_input;
static struct pgcd_io relay_alias_io;
static uint32_t relay_counts[8];static jmp_buf relay_terminal;
static void*relay_inaccessible;
static void relay_count(uint32_t out[8])
{
    const uint32_t values[]={leaf_arches,leaf_maps,leaf_saves,leaf_restores,leaf_pages,arches,saves,restores};
    memcpy(out,values,sizeof(values));
}
static void relay_mutate(unsigned point)
{
    if(relay_hit||!relay_mode||point!=relay_point||active_route!=relay_route||cur->slot!=relay_slot||
       !cur->call.attempted||!cur->call.io.opaque)return;
    struct pcmp_live*l=cur->call.io.opaque;assert(l->r==cur);relay_before=*l;
    switch(relay_mode){
    case 1:relay_alias_input=*l->caller_input;l->caller_input=&relay_alias_input;break;
    case 2:relay_alias_io=*l->caller_io;l->caller_io=&relay_alias_io;break;
    case 3:l->r=(void*)8;break;
    case 4:l->caller_input=relay_inaccessible;break;
    case 5:((uint8_t*)l)[relay_byte]^=1;break;
    case 6:l->original_io.order=0;break;
    case 7:{const struct pcmp_input*old=l->caller_input;l->caller_input=(void*)8;l->caller_input=old;break;}
    default:assert(0);
    }
    relay_after=*l;relay_count(relay_counts);relay_hit=1;
}
static int relay_arch(void*o,struct pgcd_arch*a)
{
    int ok=current_arch(o,a);
    if(a==&cur->call.before)relay_mutate(0);else if(a==&cur->call.after)relay_mutate(4);
    else if(a==&cur->final_arch)relay_mutate(7);return ok;
}
static int relay_save(void*o,struct pgcd_fp_guard*g)
{int ok=current_save(o,g);if(g==&cur->call.fp)relay_mutate(1);return ok;}
static int relay_restore(void*o,struct pgcd_fp_guard*g)
{int ok=current_restore(o,g);if(g==&cur->call.fp)relay_mutate(5);return ok;}
static int relay_map(void*o,struct efi_system*sys,struct pgcd_map*m,void*data)
{int ok=current_map(o,sys,m,data);relay_mutate(3);return ok;}
static void relay_order(void*o)
{current_order(o);relay_mutate(2);}
static int relay_page(struct ppli_at*a)
{int ok=current_page(a);relay_mutate(6);return ok;}
static int relay_dispatch(void*o,struct efi_system*sys,struct pgcd_map*m,void*data)
{if(!dispatch_relay(o,sys,m,data))longjmp(relay_terminal,1);return 1;}
static void relay_fixture(void)
{
    dispatch_fixture();original_io.arch=relay_arch;original_io.map=relay_map;
    original_io.fp_save=relay_save;original_io.fp_restore=relay_restore;original_io.order=relay_order;
    current_fixture_page=relay_page;
    for(unsigned n=0;n<6;n++){routes[n].context->io=original_io;routes[n].context->io.map=relay_dispatch;}
    relay_point=relay_mode=relay_byte=relay_route=relay_slot=relay_hit=0;
    memset(&relay_before,0,sizeof(relay_before));memset(&relay_after,0,sizeof(relay_after));memset(relay_counts,0,sizeof(relay_counts));
}
static int relay_run(unsigned n,unsigned slot)
{
    activate(n);if(setjmp(relay_terminal))return 0;
    if(!slot)return pgcd_open(c);
    if(!pgcd_open(c))return 0;
    if(n)return pgcd_map_read(c,1);
    for(unsigned k=0;k<4;k++){const struct pgcd_observation*observation=0;if(!pgcd_query_page(c,pgcd_pages[k],&observation))return 0;}
    return pgcd_finish(c);
}
static void relay_refused(void)
{
    uint32_t now[8];relay_count(now);
    assert(relay_hit&&!cur->complete&&cur->unknown==1&&cur->error==8&&!r->map_guard[relay_slot].fp.restored);
    assert(memcmp(&relay_before,&relay_after,sizeof(relay_before))&&!memcmp(now,relay_counts,sizeof(now)));
    if(relay_point<=2)assert(!cur->call.issued&&!cur->call.returned&&!cur->header_AT.issued);
    if(relay_point==2)assert(cur->call.error==PWMC_CONTEXT&&cur->call.unknown);
    if(relay_point==5||relay_point==6||relay_point==7)assert(cur->call.fp.restored==1);
}
static void relay_pair(const char*base,const char*tag)
{
    char path[1024];assert(snprintf(path,sizeof(path),"%s.%s-%u",base,tag,relay_point)>0);
    FILE*f=fopen(path,"wb");uint32_t info[8]={1,relay_route,relay_slot,relay_point,relay_mode,relay_byte,relay_hit,0},after[8];relay_count(after);
    assert(f&&fwrite(info,1,sizeof(info),f)==sizeof(info)&&fwrite(&relay_before,1,sizeof(relay_before),f)==sizeof(relay_before)&&
        fwrite(&relay_after,1,sizeof(relay_after),f)==sizeof(relay_after)&&fwrite(relay_counts,1,sizeof(relay_counts),f)==sizeof(relay_counts)&&
        fwrite(after,1,sizeof(after),f)==sizeof(after)&&fwrite(cur,1,sizeof(*cur),f)==sizeof(*cur)&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&!fclose(f));
}
int main(int argc,char**argv)
{
    assert(argc==3&&!posix_memalign((void**)&arena,4096,0x1001000));
    assert(!posix_memalign((void**)&payload_data,4096,4096)&&!posix_memalign((void**)&log_data,4096,4096));
    relay_inaccessible=mmap(0,4096,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);assert(relay_inaccessible!=MAP_FAILED);
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    unsigned checks=0;relay_fixture();
    for(unsigned pass=0;pass<6;pass++){
        unsigned n=pass<5?pass+1:0;activate(n);assert(!setjmp(relay_terminal));
        if(n){assert(pgcd_open(c));if(n<5)assert(pgcd_map_read(c,1));}
        else{for(unsigned k=0;k<4;k++){const struct pgcd_observation*observation=0;assert(pgcd_query_page(c,pgcd_pages[k],&observation));}assert(pgcd_finish(c));}
        for(unsigned k=0;k<(n==5?1u:2u);k++)assert(routes[n].frames[k].complete&&!routes[n].frames[k].error&&!routes[n].frames[k].unknown);
        checks++;
    }
    assert(leaf_maps==11&&pwmc_zero(&routes[5].frames[1],sizeof(struct pcmp_result)));
    f=fopen(argv[2],"wb");assert(f);for(unsigned n=0;n<6;n++)assert(fwrite(routes[n].source,1,sizeof(struct pgcd_result),f)==sizeof(struct pgcd_result)&&fwrite(routes[n].frames,1,2*sizeof(struct pcmp_result),f)==2*sizeof(struct pcmp_result));assert(!fclose(f));
    for(unsigned n=0;n<6;n++)for(unsigned slot=0;slot<(n==5?1u:2u);slot++)for(unsigned point=0;point<8;point++)for(unsigned mode=1;mode<=6;mode++){
        if(mode==5)continue;
        relay_fixture();relay_route=n;relay_slot=slot;relay_point=point;relay_mode=mode;
        assert(!relay_run(n,slot));relay_refused();checks++;
        if(n==1&&!slot&&(mode==1||mode==3||mode==4))relay_pair(argv[2],mode==1?"alias":mode==3?"bad-pointer":"PROT_NONE");
    }
    for(unsigned point=0;point<8;point++)for(unsigned byte=0;byte<sizeof(struct pcmp_live);byte++){
        relay_fixture();relay_route=1;relay_point=point;relay_mode=5;relay_byte=byte;
        assert(!relay_run(1,0));relay_refused();checks++;
    }
    /* A changed-then-restored control value remains indistinguishable. This
     * is an explicit limitation, not an owner/ABA/future-IRQ qualification. */
    relay_fixture();relay_route=1;relay_mode=7;relay_point=2;
    assert(relay_run(1,0)&&relay_hit&&cur->complete&&r->map_guard[0].fp.restored&&
        !memcmp(&relay_before,&relay_after,sizeof(relay_before)));checks++;
    printf("{\"passed\":true,\"checks\":%u,\"SOFTWARE_only\":true,\"existing_maps\":11,\"actual_control_bytes\":%zu,\"callback_boundaries\":8,\"whole_constructor_or_physical\":false,\"owner_lifetime_ABA_qualified\":false}\n",checks,sizeof(struct pcmp_live));
    return 0;
}
