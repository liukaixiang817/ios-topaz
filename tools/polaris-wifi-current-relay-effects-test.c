/* Callee effects on the real active relay's resident result. All leaves are
 * SOFTWARE peers; original PE and completed pointers remain inert DATA. */
#define _DARWIN_C_SOURCE 1
#define POLARIS_CURRENT_GRAPH_FIXTURE_ONLY 1
#define POLARIS_CURRENT_RELAY_EFFECTS_FIXTURE 1
#include "polaris-wifi-current-graph-test.c"
#include <sys/mman.h>
#include <unistd.h>
static unsigned effect_point,effect_route,effect_slot,effect_mode,effect_hit,effect_armed;
static size_t effect_byte,effect_core_bytes;
static struct pcmp_result effect_before,effect_after;
static struct pcmp_live effect_control_before,effect_control_after;
static uint32_t effect_counts[8];
static void effect_count(uint32_t out[8])
{
    const uint32_t values[]={leaf_arches,leaf_maps,leaf_saves,leaf_restores,leaf_pages,arches,saves,restores};
    memcpy(out,values,sizeof(values));
}
static void effect_begin(unsigned point)
{
    if(effect_hit||!effect_mode||point!=effect_point||active_route!=effect_route||cur->slot!=effect_slot||
       !cur->call.attempted||!cur->call.io.opaque)return;
    struct pcmp_live*l=cur->call.io.opaque;assert(l->r==cur);
    effect_before=*cur;effect_control_before=*l;effect_armed=1;
}
static void effect_end(unsigned point)
{
    if(!effect_armed||point!=effect_point)return;effect_armed=0;
    struct pcmp_live*l=cur->call.io.opaque;uint8_t*data=(uint8_t*)cur;
    if(effect_mode==4)l->caller_input=(void*)8;
    if(effect_mode==5){uint8_t old=data[effect_byte];data[effect_byte]^=1;data[effect_byte]=old;}
    else data[effect_byte]^=1;
    effect_after=*cur;effect_control_after=*l;effect_count(effect_counts);effect_hit=1;
    if(effect_mode==3){
        assert(!mprotect(graph_core,effect_core_bytes,PROT_NONE));
        assert(!mprotect(graph_pool,0x40000,PROT_NONE));
    }
}
static int effect_bool(int ok)
{return effect_hit&&effect_mode==2?0:ok;}
static int effect_arch(void*o,struct pgcd_arch*a)
{
    unsigned point=a==&cur->call.before?0:a==&cur->call.after?4:a==&cur->final_arch?7:99;
    effect_begin(point);int ok=graph_arch(o,a);effect_end(point);return effect_bool(ok);
}
static int effect_save(void*o,struct pgcd_fp_guard*g)
{effect_begin(1);int ok=current_save(o,g);effect_end(1);return effect_bool(ok);}
static int effect_restore(void*o,struct pgcd_fp_guard*g)
{effect_begin(5);int ok=current_restore(o,g);effect_end(5);return effect_bool(ok);}
static int effect_map(void*o,struct efi_system*system,struct pgcd_map*m,void*data)
{effect_begin(3);int ok=graph_map(o,system,m,data);effect_end(3);return effect_bool(ok);}
static void effect_order(void*o)
{effect_begin(2);current_order(o);effect_end(2);}
static int effect_page(struct ppli_at*a)
{effect_begin(6);int ok=graph_page(a);effect_end(6);return effect_bool(ok);}
static void effect_fixture(void)
{
    graph_fixture(1);original_io.arch=effect_arch;original_io.map=effect_map;
    original_io.fp_save=effect_save;original_io.fp_restore=effect_restore;original_io.order=effect_order;
    current_fixture_page=effect_page;
    for(unsigned n=0;n<6;n++){routes[n].context->io=original_io;routes[n].context->io.map=graph_relay;}
    effect_point=effect_route=effect_slot=effect_mode=effect_hit=effect_armed=0;effect_byte=0;
    memset(&effect_before,0,sizeof(effect_before));memset(&effect_after,0,sizeof(effect_after));
    memset(&effect_control_before,0,sizeof(effect_control_before));memset(&effect_control_after,0,sizeof(effect_control_after));
    memset(effect_counts,0,sizeof(effect_counts));
}
static int effect_run(unsigned route,unsigned slot)
{activate(route);return graph_temporal_run(route,slot);}
static void effect_refused(void)
{
    uint32_t now[8];effect_count(now);
    assert(effect_hit&&graph_stopped&&cur->unknown&&cur->error&&!r->map_guard[effect_slot].fp.restored);
    assert(!memcmp(now,effect_counts,sizeof(now)));
    if(effect_mode==4)assert(cur->error==8);
    else if(effect_byte!=offsetof(struct pcmp_result,error))assert(cur->error==9);
    /* Completion, padding or status poison is retained; it is never cleared
     * to manufacture a clean failure or a successful completed record. */
    if(effect_point==2)assert(cur->call.error&&cur->call.unknown);
    if(effect_point>=5)assert(cur->call.fp.restored);
}
static void effect_pair(const char*base,const char*tag)
{
    char path[1024];assert(snprintf(path,sizeof(path),"%s.%s-%u",base,tag,effect_point)>0);
    FILE*f=fopen(path,"wb");uint32_t info[8]={1,effect_route,effect_slot,effect_point,effect_mode,(uint32_t)effect_byte,effect_hit,0},after[8];effect_count(after);
    assert(f&&fwrite(info,1,sizeof(info),f)==sizeof(info)&&
        fwrite(&effect_before,1,sizeof(effect_before),f)==sizeof(effect_before)&&
        fwrite(&effect_after,1,sizeof(effect_after),f)==sizeof(effect_after)&&
        fwrite(&effect_control_before,1,sizeof(effect_control_before),f)==sizeof(effect_control_before)&&
        fwrite(&effect_control_after,1,sizeof(effect_control_after),f)==sizeof(effect_control_after)&&
        fwrite(effect_counts,1,sizeof(effect_counts),f)==sizeof(effect_counts)&&fwrite(after,1,sizeof(after),f)==sizeof(after)&&
        fwrite(cur,1,sizeof(*cur),f)==sizeof(*cur)&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&!fclose(f));
}
static int effect_allowed(unsigned point,size_t byte)
{
    /* Independent ABI spans of the actual arguments, not a call to the
     * production hash helper or a returned-Map self-qualification. */
    const size_t start[]={287208,287424,0,287160,287312,287424,353728,353784};
    const size_t bytes[]={104,176,0,36,104,176,56,104};
    return (byte>=start[point]&&byte-start[point]<bytes[point])||
        (point==3&&byte>=288152&&byte-288152<8192);
}
int main(int argc,char**argv)
{
    assert(argc==3&&!posix_memalign((void**)&arena,4096,0x1001000));
    assert(!posix_memalign((void**)&payload_data,4096,4096)&&!posix_memalign((void**)&log_data,4096,4096));
    long host_page=sysconf(_SC_PAGESIZE);assert(host_page>0&&0x40000%(size_t)host_page==0);
    effect_core_bytes=(PGCI_IMAGE_BYTES+(size_t)host_page-1)/(size_t)host_page*(size_t)host_page;
    graph_core=mmap(0,effect_core_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    graph_pool=mmap(0,0x40000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(graph_core!=MAP_FAILED&&graph_pool!=MAP_FAILED);
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");
    assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    unsigned checks=0;effect_fixture();
    for(unsigned pass=0;pass<6;pass++){
        unsigned n=pass<5?pass+1:0;activate(n);
        if(n){assert(graph_open());if(n<5)assert(pgcd_map_read(c,1));}
        else{for(unsigned k=0;k<4;k++){const struct pgcd_observation*observation=0;assert(pgcd_query_page(c,pgcd_pages[k],&observation));}assert(pgcd_finish(c));}
        for(unsigned k=0;k<(n==5?1u:2u);k++)assert(routes[n].frames[k].complete&&graphs[n][k].complete&&!routes[n].frames[k].error);
        checks++;
    }
    assert(leaf_maps==11&&pwmc_zero(&routes[5].frames[1],sizeof(struct pcmp_result)));
    f=fopen(argv[2],"wb");assert(f);for(unsigned n=0;n<6;n++)assert(fwrite(routes[n].source,1,sizeof(struct pgcd_result),f)==sizeof(struct pgcd_result)&&
        fwrite(routes[n].frames,1,2*sizeof(struct pcmp_result),f)==2*sizeof(struct pcmp_result)&&
        fwrite(graphs[n],1,2*sizeof(struct pcmg_result),f)==2*sizeof(struct pcmg_result));assert(!fclose(f));
    const size_t shapes[]={356687,286456,353688,296344,287196};
    for(unsigned route=0;route<6;route++)for(unsigned slot=0;slot<(route==5?1u:2u);slot++)for(unsigned point=0;point<8;point++)for(unsigned shape=0;shape<5;shape++){
        effect_fixture();effect_route=route;effect_slot=slot;effect_point=point;effect_mode=1;effect_byte=shapes[shape];
        assert(!effect_allowed(point,effect_byte)&&!effect_run(route,slot));effect_refused();checks++;
        if(route==1&&!slot&&(shape==0||shape==3))effect_pair(argv[2],shape?"beyond-capacity":"padding");
    }
    /* Retained object edges and every page boundary exercise the large
     * record, including padding and unissued RAW. */
    const size_t edges[]={0,119,120,191,192,663,664,28599,286456,286487,286488,286495,
        286496,287159,287160,287195,287196,287207,287208,287311,287312,287415,287416,287423,
        287424,287599,287600,288151,288152,296343,296344,353687,353688,353719,353720,353727,
        353728,353783,353784,353887,353888,356615,356616,356620,356624,356628,356632,356636,
        356640,356644,356648,356651,356652,356683,356684,356687};
    for(unsigned point=0;point<8;point++)for(unsigned pick=0;pick<sizeof(edges)/sizeof(edges[0])+2*(sizeof(struct pcmp_result)/4096);pick++){
        size_t byte=pick<sizeof(edges)/sizeof(edges[0])?edges[pick]:
            4096*((pick-sizeof(edges)/sizeof(edges[0]))/2+1)-((pick-sizeof(edges)/sizeof(edges[0]))%2);
        if(effect_allowed(point,byte))continue;
        effect_fixture();effect_route=1;effect_point=point;effect_mode=1;effect_byte=byte;
        assert(!effect_run(1,0));effect_refused();checks++;
    }
    for(unsigned point=0;point<8;point++)for(unsigned mode=2;mode<=4;mode++){
        effect_fixture();effect_route=1;effect_point=point;effect_mode=mode;effect_byte=356687;
        assert(!effect_run(1,0));
        /* Host-only protection is removed after terminal unwinding solely
         * to inspect inert DATA and prepare the next host fixture. */
        if(mode==3){assert(!mprotect(graph_core,effect_core_bytes,PROT_READ|PROT_WRITE));assert(!mprotect(graph_pool,0x40000,PROT_READ|PROT_WRITE));}
        effect_refused();checks++;effect_pair(argv[2],mode==2?"false-return":mode==3?"PROT_NONE":"control-first");
    }
    /* The returned map may fill any byte of its real 8KiB output, even past
     * its returned descriptor prefix. No claim is made for the 64KiB backing. */
    effect_fixture();effect_route=1;effect_point=3;effect_mode=1;effect_byte=296343;
    assert(effect_run(1,0)&&effect_hit&&cur->complete&&graphs[1][0].complete&&cur->call.data[8191]==1);checks++;
    effect_pair(argv[2],"inside-capacity");
    effect_fixture();effect_route=1;effect_point=3;effect_mode=5;effect_byte=296344;
    assert(effect_run(1,0)&&effect_hit&&cur->complete&&graphs[1][0].complete);checks++;
    effect_pair(argv[2],"equal-after");
    printf("{\"passed\":true,\"checks\":%u,\"SOFTWARE_only\":true,\"existing_maps\":11,\"resident_result_bytes\":%zu,\"callback_boundaries\":8,\"Map_output_capacity\":8192,\"whole_constructor_or_physical\":false,\"external_effects_owner_lifetime_ABA_qualified\":false}\n",checks,sizeof(struct pcmp_result));
    return 0;
}
