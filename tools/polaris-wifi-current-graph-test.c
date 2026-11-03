/* Real six-route generic caller + later relay + shared DATA walk.
 * Every service/AT/FP/clock is a SOFTWARE peer; original PE is inert DATA.
 * This is post-map INPUT evidence, never whole power/client qualification. */
#define POLARIS_WIFI_CURRENT_GRAPH_INPUT 1
#define POLARIS_CURRENT_MAP_DISPATCH_FIXTURE_ONLY 1
#include "polaris-wifi-current-map-dispatch-test.c"
#include "uefi-wifi-current-graph.h"
#include <setjmp.h>
static struct pcmg_result(*graphs)[2];
static struct pcmg_result*active_graph;
static struct pcmp_live*active_parent;
static uint8_t*graph_core,*graph_pool;
static unsigned graph_running,graph_ATs,graph_clocks,graph_calls;
static unsigned graph_mode,graph_point,graph_fault,graph_byte,graph_hit,graph_stopped,graph_gcd_count;
static unsigned graph_entry_fault;
static unsigned graph_temporal_fault,graph_temporal_slot,graph_temporal_hit,graph_handoff_fault,graph_handoff_hit,graph_handoff_arches;
static uint64_t graph_clock_floor;
#if defined(POLARIS_CURRENT_PROVIDER_FIXTURE)
static int fixture_provider_capture(struct pcmp_live*,int(*)(struct ppli_at*));
static int fixture_provider_minimum(const struct pgcd_context*,unsigned,uint64_t*);
#endif
static jmp_buf graph_terminal;
static int graph_mutate(struct ppli_at*at,struct pgcd_arch*clock)
{
    unsigned point=at?graph_ATs:graph_clocks;
    if(!graph_running||graph_hit||!graph_fault||graph_mode!=(at?1u:2u)||graph_point!=point)return 1;
    graph_hit=1;
    switch(graph_fault){
    case 1:return 0;
    case 2:if(at)at->returned=0;else clock->cpu.el=8;break;
    case 3:*cpu_flag=1;break;
    case 4:active_parent->r=(void*)8;break;
    case 5:active_parent->caller_input=(void*)8;break;
    case 6:active_parent->original_io.arch=0;break;
    case 7:active_graph->binding.parent.r=(void*)8;break;
    case 8:active_graph->graph.input.call=(void*)8;break;
    case 9:c->record=(void*)8;active_parent->r->context_before.record=(void*)8;break;
    case 10:active_parent->r->input.image=(void*)8;break;
    case 11:active_graph->parent_after.r=(void*)8;break;
    case 12:((uint8_t*)active_parent)[graph_byte]^=1;break;
    case 13:put(core+0x1cdb0,1235,8);break;
    case 14:assert(clock);clock->cpu.ticks=active_graph->graph.arch_returned?
        active_graph->graph.clock[active_graph->graph.arch_returned-1].raw.cpu.ticks-1:active_graph->binding.minimum-1;break;
    case 15:assert(clock);clock->cpu.ticks=active_graph->binding.opening+PGCD_FRESH_TICKS+1;break;
    case 16:active_graph->graph.call.data[65535]=active_parent->r->call.data[65535]=1;break;
    case 17:((uint8_t*)active_graph)[graph_byte]^=1;break;
    case 18:put(core+0x1d1a8,pwfi_le(core+0x1d1a8,8)^16,8);put(core+0x1d1a8,pwfi_le(core+0x1d1a8,8)^16,8);break;
    case 19:((uint8_t*)active_parent->r)[graph_byte]^=1;break;
    default:assert(0);
    }return 1;
}
static int graph_page(struct ppli_at*a)
{int ok=current_page(a);if(graph_running){graph_ATs++;if(!graph_mutate(a,0))return 0;}return ok;}
static int graph_arch(void*o,struct pgcd_arch*a)
{
    int ok=current_arch(o,a);if(a->cpu.ticks<graph_clock_floor)a->cpu.ticks=graph_clock_floor;
    if(graph_running){graph_clocks++;if(!graph_mutate(0,a))return 0;}
    else if(graph_temporal_fault&&!graph_temporal_hit&&active_graph&&active_graph->complete&&
        active_graph->binding.slot==graph_temporal_slot){
        const struct pbgi_result*g=&active_graph->graph;uint64_t latest=g->clock[g->arch_returned-1].raw.cpu.ticks;
        graph_temporal_hit=1;
        switch(graph_temporal_fault){
        case 1:a->cpu.ticks=latest-1;break;
        case 2:a->cpu.ticks=cur->final_arch.cpu.ticks;break;
        case 3:a->cpu.ticks=latest;break;
        case 4:a->cpu.ticks=latest+1;break;
        case 5:graph_clock_floor=a->cpu.ticks=active_graph->binding.opening+PGCD_FRESH_TICKS;break;
        case 6:a->cpu.ticks=active_graph->binding.opening+PGCD_FRESH_TICKS+1;break;
        case 7:a->cpu.ticks=UINT64_MAX;break;
        default:assert(0);
        }
    }return ok;
}
static int graph_map(void*o,struct efi_system*system,struct pgcd_map*m,void*out)
{
    (void)o;assert(system==s);leaf_maps++;
    struct efi_memory rows[7]={{3,0,(uintptr_t)arena,0,fixture_image_bytes/4096,8},
        {3,0,(uintptr_t)graph_core,0,PGCI_IMAGE_BYTES/4096,8},{4,0,(uintptr_t)graph_pool,0,0x40,8},
        {2,0,0xc0000000,0,512,8},{2,0,(uintptr_t)payload_data,0,1,8},{2,0,(uintptr_t)log_data,0,1,8},
        {6,0,(uintptr_t)cfg,0,1,UINT64_C(0x800000000000000f)}};
    for(unsigned k=0;k<7;k++){memcpy((uint8_t*)out+48*k,&rows[k],40);memset((uint8_t*)out+48*k+40,0x5a,8);}
    /* Deliberately different SOFTWARE accounting inputs at every real Map.
     * These values are consistency DATA, never active allocation inventory. */
    put(core+0x1d1a8,120*graph_gcd_count+16*leaf_maps,8);
    m->status=0;m->bytes=7*48;m->key=1234;m->stride=48;m->version=1;return 1;
}
static int pcmp_parent_graph(struct pcmp_live*parent,int(*read_page)(struct ppli_at*))
{
#if defined(POLARIS_CURRENT_PROVIDER_FIXTURE)
    assert(read_page==current_fixture_page);
#else
    assert(read_page==graph_page);
#endif
    graph_calls++;graph_running=1;graph_ATs=graph_clocks=0;
    active_parent=parent;active_graph=&graphs[active_route][parent->r->slot];
    struct pcmp_route entry_routes[PCMP_PARENT_CONTEXTS];memcpy(entry_routes,routes,sizeof(entry_routes));
    struct pcmg_result(*output)[2]=graphs;unsigned count=PCMP_PARENT_CONTEXTS;
    switch(graph_entry_fault){
    case 0:break;case 1:count--;break;case 2:parent->r=(void*)8;break;case 3:output=(void*)8;break;
    case 4:output=(void*)((uintptr_t)parent->r-active_route*sizeof(*graphs));break;
    case 5:output=(void*)((uintptr_t)cpu_flag-active_route*sizeof(*graphs));break;
    case 6:entry_routes[active_route].source=(void*)8;break;case 7:entry_routes[active_route].context=(void*)8;break;
    case 8:entry_routes[active_route].ticket=(void*)8;break;case 9:parent->r=(void*)((uintptr_t)parent->r+1);break;
    case 10:parent->r->final_arch.cpu.ticks=parent->r->source_before.before.cpu.ticks+PGCD_FRESH_TICKS+1;break;
    case 11:entry_routes[active_route].path=PCMP_QUERY_PAIR;break;case 12:active_graph->reserved=1;break;
    default:assert(0);
    }
    int ok=pcmg_route_capture(entry_routes,count,output,parent,read_page);
    graph_running=0;
#if defined(POLARIS_CURRENT_PROVIDER_FIXTURE)
    if(ok)ok=fixture_provider_capture(parent,read_page);
#endif
    return ok;
}
static int pgcd_parent_map_minimum(const struct pgcd_context*caller,unsigned slot,uint64_t*out)
{
    if(graph_handoff_fault&&!graph_handoff_hit){
        struct pcmg_result*g=&graphs[active_route][slot];struct pbgi_clock*last=&g->graph.clock[g->graph.arch_returned-1];
        graph_handoff_hit=1;graph_handoff_arches=leaf_arches;
        /* Explicit SOFTWARE mutations of already completed DATA. Rehashing
         * here exercises shape/arithmetic refusal as well as digest refusal;
         * it never manufactures an opened context or a firmware observation. */
        switch(graph_handoff_fault){
        case 1:g->complete=0;break;case 2:g->unknown=1;break;
        case 3:g->graph.arch_returned=0;break;case 4:g->graph.arch_returned=PBGI_CLOCKS+1;break;
        case 5:g->graph.arch_issued--;break;case 6:last->returned=0;break;case 7:last->native[1]=1;break;
        case 8:last->raw.cpu.ticks=0;break;case 9:last->raw.cpu.ticks=g->binding.minimum-1;break;
        case 10:last->raw.cpu.ticks=g->binding.opening+PGCD_FRESH_TICKS+1;break;
        case 11:last->raw.cpu.ticks=UINT64_MAX;break;
        case 12:cur->digest[0]^=1;break;case 13:g->digest[0]^=1;break;
        default:assert(0);
        }
        if(graph_handoff_fault<13)ppli_sha(g,offsetof(struct pcmg_result,digest),g->digest);
    }
#if defined(POLARIS_CURRENT_PROVIDER_FIXTURE)
    return fixture_provider_minimum(caller,slot,out);
#else
    return pcmg_route_minimum(routes,PCMP_PARENT_CONTEXTS,graphs,caller,slot,out);
#endif
}
/* The actual parent appends raw then never returns a rejected callback.
 * This SOFTWARE terminal peer unwinds only the host test, without invoking
 * outer error cleanup or following a deliberately poisoned source pointer. */
static int graph_relay(void*o,struct efi_system*system,struct pgcd_map*m,void*data)
{int ok=dispatch_relay(o,system,m,data);if(!ok){graph_stopped=1;longjmp(graph_terminal,1);}return 1;}
static int graph_open(void)
{if(setjmp(graph_terminal))return 0;return pgcd_open(c);}
static void graph_fixture(unsigned gcd_count)
{
    dispatch_fixture();core=graph_core;memcpy(core,original,PGCI_IMAGE_BYTES);
    for(unsigned n=0;n<PGCI_RELOC_COUNT;n++)put(core+pgci_relocations[n],pwfi_le(core+pgci_relocations[n],8)+(uintptr_t)core,8);
    s->boot=(void*)(core+0x1b800);cfg[0].table=(uintptr_t)core+0x1bb18;
    graphs=(void*)(arena+0xa00000);assert((uint8_t*)graphs+sizeof(*graphs)*PCMP_PARENT_CONTEXTS<arena+fixture_image_bytes);
    memset(graphs,0,sizeof(*graphs)*PCMP_PARENT_CONTEXTS);memset(graph_pool,0,0x40000);
    uint64_t lows[7]={(uintptr_t)arena,(uintptr_t)core,(uintptr_t)graph_pool,0xc0000000,(uintptr_t)payload_data,(uintptr_t)log_data,(uintptr_t)cfg};
    uint64_t sizes[7]={fixture_image_bytes,PGCI_IMAGE_BYTES,0x40000,0x200000,4096,4096,4096};unsigned types[7]={3,3,4,2,2,2,6};
    uint64_t head=(uintptr_t)core+0x1b358;
    for(unsigned k=0;k<7;k++){
        uint8_t*n=graph_pool+4096*k;put(n,0x70616d6d,8);put(n+8,k==6?head:(uintptr_t)(n+4096)+8,8);
        put(n+16,k?(uintptr_t)(n-4096)+8:head,8);n[24]=1;put(n+28,types[k],4);
        put(n+32,lows[k],8);put(n+40,lows[k]+sizes[k]-1,8);put(n+56,types[k]==6?UINT64_C(0x800000000000000f):8,8);
    }
    put(core+0x1b358,(uintptr_t)graph_pool+8,8);put(core+0x1b360,(uintptr_t)graph_pool+6*4096+8,8);
    head=(uintptr_t)core+0x1bd60;
    for(unsigned k=0;k<gcd_count;k++){
        uint8_t*h=graph_pool+0x10000+128*k,*n=h+24;put(h,0x30646870,4);put(h+8,4,4);put(h+16,120,8);
        put(n,0x6d646367,8);put(n+8,k+1==gcd_count?head:(uintptr_t)(h+128)+32,8);put(n+16,k?(uintptr_t)(h-128)+32:head,8);
        put(n+24,k*UINT64_C(0x100000),8);put(n+32,(k+1)*UINT64_C(0x100000)-1,8);put(n+40,8,8);put(n+48,8,8);put(n+56,2,4);
        put(h+104,0x6c617470,4);put(h+112,120,8);
    }
    put(core+0x1bd60,(uintptr_t)graph_pool+0x10000+32,8);put(core+0x1bd68,(uintptr_t)graph_pool+0x10000+128*(gcd_count-1)+32,8);
    const unsigned locks[3]={0x1b340,0x1bd48,0x1c1f8};for(unsigned k=0;k<3;k++){put(core+locks[k],16,8);put(core+locks[k]+8,4,8);put(core+locks[k]+16,1,4);}
    put(core+0x1cdb0,1234,8);put(core+0x1cc08,0,8);put(core+0x1dc10,0,8);put(core+0x1cb78,0,8);put(core+0x1d1b0,4,4);
    original_io.arch=graph_arch;original_io.map=graph_map;current_fixture_page=graph_page;
    for(unsigned n=0;n<PCMP_PARENT_CONTEXTS;n++){routes[n].context->io=original_io;routes[n].context->io.map=graph_relay;}
    graph_running=graph_calls=graph_ATs=graph_clocks=0;active_graph=0;active_parent=0;
    graph_mode=graph_point=graph_fault=graph_byte=graph_hit=graph_stopped=0;graph_gcd_count=gcd_count;
    graph_entry_fault=0;
    graph_temporal_fault=graph_temporal_slot=graph_temporal_hit=graph_handoff_fault=graph_handoff_hit=graph_handoff_arches=0;
    graph_clock_floor=0;
}
static void graph_raw(const char*base,const char*suffix,const void*data,size_t bytes)
{char name[4096];int n=snprintf(name,sizeof(name),"%s%s",base,suffix);assert(n>0&&(size_t)n<sizeof(name));
 FILE*f=fopen(name,"wb");assert(f&&fwrite(data,1,bytes,f)==bytes&&!fclose(f));}
static void graph_pair_raw(const char*base,const char*suffix)
{char name[4096];int n=snprintf(name,sizeof(name),"%s%s",base,suffix);assert(n>0&&(size_t)n<sizeof(name));
 FILE*f=fopen(name,"wb");assert(f&&fwrite(cur,1,sizeof(*cur),f)==sizeof(*cur)&&
     fwrite(active_graph,1,sizeof(*active_graph),f)==sizeof(*active_graph)&&!fclose(f));}
static void graph_temporal_raw(const char*base,const char*suffix)
{char name[4096];int n=snprintf(name,sizeof(name),"%s%s",base,suffix);assert(n>0&&(size_t)n<sizeof(name));
 FILE*f=fopen(name,"wb");assert(f&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&fwrite(cur,1,sizeof(*cur),f)==sizeof(*cur)&&
     fwrite(active_graph,1,sizeof(*active_graph),f)==sizeof(*active_graph)&&!fclose(f));}
static int graph_temporal_run(unsigned index,unsigned slot)
{
    if(!slot)return graph_open();
    if(index){if(!graph_open())return 0;return pgcd_map_read(c,1);}
    for(unsigned k=0;k<4;k++){const struct pgcd_observation*observation=0;if(!pgcd_query_page(c,pgcd_pages[k],&observation))return 0;}
    return pgcd_finish(c);
}
#ifndef POLARIS_CURRENT_GRAPH_FIXTURE_ONLY
int main(int argc,char**argv)
{
    assert(argc==3&&!posix_memalign((void**)&arena,4096,0x1001000));
    assert(!posix_memalign((void**)&payload_data,4096,4096)&&!posix_memalign((void**)&log_data,4096,4096));
    assert(!posix_memalign((void**)&graph_core,4096,PGCI_IMAGE_BYTES)&&!posix_memalign((void**)&graph_pool,4096,0x40000));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");
    assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    unsigned checks=0;graph_fixture(1);
    for(unsigned pass=0;pass<PCMP_PARENT_CONTEXTS;pass++){
        unsigned n=pass<5?pass+1:0;activate(n);
        if(n){assert(graph_open()&&c->opened==1&&!c->finished&&ticket->spent==1);
            if(n<5)assert(pgcd_map_read(c,1)&&!c->finished&&r->phase==1);}
        else {for(unsigned k=0;k<4;k++){const struct pgcd_observation*observation=0;assert(pgcd_query_page(c,pgcd_pages[k],&observation));}
            assert(pgcd_finish(c)&&c->finished&&r->phase==2&&queries==8);}
        for(unsigned k=0;k<(n==5?1u:2u);k++){
            const struct pcmg_result*g=&graphs[n][k];const struct pcmp_result*m=&routes[n].frames[k];
            assert(m->complete&&!m->unknown&&!m->error&&g->complete&&!g->unknown&&!g->error&&g->parent_copied==1);
            assert(g->binding.index==n&&g->binding.slot==k&&g->binding.parent.r==m&&g->binding.route.context==c);
            assert(g->binding.opening==r->before.cpu.ticks&&g->binding.minimum==m->final_arch.cpu.ticks);
            assert(g->graph.input.call==&m->call&&g->graph.input.io.arch==graph_arch&&g->graph.call.io.arch==pcmp_arch);
            assert(g->graph.call.io.opaque==(void*)(uintptr_t)g->binding.parent_address&&g->graph.input.io.opaque==original_io.opaque);
            assert(g->graph.core_pages==57&&g->graph.count[0]==7&&g->graph.count[1]==1&&g->graph.arch_returned==69);
            assert(g->graph.clock[0].raw.cpu.ticks>=g->binding.minimum&&graph_ATs==66&&graph_clocks==69);
            assert(pgcd_equal(&g->binding.parent,&g->parent_after,sizeof(g->parent_after)));checks++;
        }
    }
    assert(leaf_maps==11&&graph_calls==11&&pwmc_zero(&graphs[5][1],sizeof(graphs[5][1])));checks++;
    FILE*out=fopen(argv[2],"wb");assert(out);
    for(unsigned n=0;n<6;n++){assert(fwrite(routes[n].frames,sizeof(struct pcmp_result),2,out)==2);assert(fwrite(graphs[n],sizeof(struct pcmg_result),2,out)==2);}
    assert(!fclose(out));
    /* Closed records contain expired stack addresses. Reject from own known
     * frame flags before ever following their captured caller/relay pointers. */
    for(unsigned n=0;n<6;n++)for(unsigned k=0;k<(n==5?1u:2u);k++){
        struct pcmp_live closed=graphs[n][k].binding.parent;closed.caller_input=(void*)8;closed.caller_io=(void*)8;
        unsigned before_maps=leaf_maps,before_AT=leaf_pages,before_clocks=leaf_arches;
        assert(!pcmg_route_capture(routes,6,graphs,&closed,graph_page));
        assert(leaf_maps==before_maps&&leaf_pages==before_AT&&leaf_arches==before_clocks);checks++;
    }
    graph_fixture(256);activate(1);assert(graph_open()&&active_graph->graph.count[1]==256&&graph_ATs==321&&graph_clocks==324);
    graph_pair_raw(argv[2],".max");checks++;
    graph_fixture(257);activate(1);assert(!graph_open()&&graph_stopped&&active_graph->graph.count[1]==256&&active_graph->graph.error==4&&graph_ATs==321&&graph_clocks==322);checks++;
#if !defined(PCMG_NORMAL_ONLY) && !defined(PCMG_TEMPORAL_ONLY)
    for(unsigned bad=1;bad<=12;bad++){
        graph_fixture(1);activate(1);graph_entry_fault=bad;
        assert(!graph_open()&&graph_stopped&&cur->error==7&&leaf_maps==1&&graph_calls==1&&!graph_ATs&&!graph_clocks);
        assert(!r->map_guard[0].fp.restored&&cur->call.map.status==0&&cur->call.map.issued==1&&cur->call.map.returned==1);
        if(bad==10){assert(active_graph->attempted&&active_graph->unknown&&active_graph->error==1);
            graph_pair_raw(argv[2],".entry-refused");}
        else if(bad==12)assert(!active_graph->attempted&&!active_graph->unknown&&active_graph->reserved==1);
        else assert(pwmc_zero(active_graph,sizeof(*active_graph)));
        checks++;
    }
    for(unsigned mode=1;mode<=2;mode++)for(unsigned bad=1;bad<=16;bad++){
        if(bad==12||(mode==1&&(bad==14||bad==15)))continue;
        for(unsigned point=1;point<=(mode==1?66u:69u);point++){
#if defined(PCMG_SUBSET_ONLY)
            if(point!=1&&point!=3&&point!=(mode==1?66u:69u))continue;
#endif
            if(bad==13&&point<3)continue;
            graph_fixture(1);activate(1);graph_mode=mode;graph_point=point;graph_fault=bad;
            assert(!graph_open()&&graph_hit&&graph_stopped&&active_graph->unknown&&!active_graph->complete);
            assert(leaf_maps==1&&graph_calls==1&&cur->error==7&&cur->unknown&&cur->call.map.status==0&&cur->call.map.issued==1&&cur->call.map.returned==1);
            assert(!r->map_guard[0].fp.restored);
            if(bad==11)assert(!active_graph->parent_copied&&active_graph->parent_after.r==(void*)8);
            else assert(active_graph->parent_copied==1);
            if(bad!=13)assert((mode==1?graph_ATs:graph_clocks)==point);
            if(mode==2&&point==1&&bad==4)graph_pair_raw(argv[2],".parent-refused");
            checks++;
        }
        fprintf(stderr,"PROGRESS graph callback mode%u fault%u cases%u\n",mode,bad,checks);
    }
    for(unsigned mode=1;mode<=2;mode++)for(unsigned byte=0;byte<sizeof(struct pcmp_live);byte++){
#if defined(PCMG_SUBSET_ONLY)
        if(byte!=0&&byte!=sizeof(struct pcmp_live)-1)continue;
#endif
        graph_fixture(1);activate(1);graph_mode=mode;graph_point=1;graph_fault=12;graph_byte=byte;
        assert(!graph_open()&&graph_hit&&graph_stopped&&active_graph->unknown&&!active_graph->complete&&cur->error==7);
        assert(pgcd_equal(&active_graph->parent_after,&active_graph->binding.parent,byte));
        assert(((const uint8_t*)&active_graph->parent_after)[byte]==(((const uint8_t*)&active_graph->binding.parent)[byte]^1));checks++;
    }
    for(unsigned mode=1;mode<=2;mode++)for(unsigned byte=0;byte<sizeof(struct pcmg_result);byte++){
        if(byte>=offsetof(struct pcmg_result,graph)&&byte<offsetof(struct pcmg_result,parent_after))continue;
#if defined(PCMG_SUBSET_ONLY)
        if(byte!=0&&byte!=408&&byte!=sizeof(struct pcmg_result)-1)continue;
#endif
        graph_fixture(1);activate(1);graph_mode=mode;graph_point=1;graph_fault=17;graph_byte=byte;
        assert(!graph_open()&&graph_hit&&graph_stopped&&active_graph->unknown&&cur->error==7);
        /* Preserve the actual poisoned complete/copy/output bytes. UNKNOWN
         * and logical refusal take precedence over a corrupted raw flag. */
        if(byte>=offsetof(struct pcmg_result,complete)&&byte<offsetof(struct pcmg_result,complete)+4)
            assert(active_graph->complete==(1u<<(8*(byte-(unsigned)offsetof(struct pcmg_result,complete)))));
        else assert(!active_graph->complete);
        if(byte>=offsetof(struct pcmg_result,parent_after)&&byte<offsetof(struct pcmg_result,parent_after)+sizeof(struct pcmp_live)){
            assert(!active_graph->parent_copied&&((const uint8_t*)&active_graph->parent_after)[byte-(unsigned)offsetof(struct pcmg_result,parent_after)]==1);
        }
        checks++;
    }
    /* The enclosing frame's final architecture sample and unissued digest/
     * padding were outside its older partial source seal. Bind the WHOLE
     * actual frame across each new callback before following its inputs. */
    const struct {unsigned lo,hi;} frame_fields[]={
        {offsetof(struct pcmp_result,final_arch),offsetof(struct pcmp_result,header)},
        {offsetof(struct pcmp_result,digest),sizeof(struct pcmp_result)},
        {offsetof(struct pcmp_result,binding_digest)+32,offsetof(struct pcmp_result,call)}
    };
    for(unsigned mode=1;mode<=2;mode++)for(unsigned field=0;field<3;field++)
        for(unsigned byte=frame_fields[field].lo;byte<frame_fields[field].hi;byte++){
#if defined(PCMG_SUBSET_ONLY)
            if(byte!=frame_fields[field].lo&&byte!=frame_fields[field].hi-1)continue;
#endif
            graph_fixture(1);activate(1);graph_mode=mode;graph_point=1;graph_fault=19;graph_byte=byte;
            assert(!graph_open()&&graph_hit&&graph_stopped&&active_graph->unknown&&!active_graph->complete&&cur->error==7);
            if(mode==2&&byte==offsetof(struct pcmp_result,final_arch))graph_pair_raw(argv[2],".frame-refused");
            checks++;
        }
    /* An enqueue/owner-shaped SOFTWARE RAM ABA can still pass snapshots.
     * No callback or owner exclusion is inferred from the completed graph. */
    graph_fixture(1);activate(1);graph_mode=2;graph_point=69;graph_fault=18;
    assert(graph_open()&&graph_hit&&active_graph->complete&&!active_graph->unknown);checks++;
#endif
#if !defined(PCMG_NORMAL_ONLY)
    for(unsigned n=0;n<6;n++)for(unsigned slot=0;slot<(n==5?1u:2u);slot++)for(unsigned bad=1;bad<=7;bad++){
        graph_fixture(1);activate(n);graph_temporal_fault=bad;graph_temporal_slot=slot;
        int ok=graph_temporal_run(n,slot);int expected=bad>=3&&bad<=5;
        assert(ok==expected&&graph_temporal_hit&&active_graph->complete&&!active_graph->unknown&&cur->complete&&!cur->unknown);
        const struct pgcd_service_guard*g=&r->map_guard[slot];
        if(expected){assert(g->fp.restored&&g->left&&!g->unknown&&!r->uncertain);}
        else {assert(!g->fp.restored&&!g->left&&g->unknown&&r->uncertain&&r->error==(bad==7?PGCD_ARCH:PGCD_CLOCK)&&
            r->map[slot].status==0&&r->map[slot].issued==1&&r->map[slot].returned==1);}
        if(n==1&&!slot&&(bad==1||bad==3||bad==6))graph_temporal_raw(argv[2],bad==1?".temporal-refused":bad==3?".temporal-equal":".temporal-expired");
        checks++;
    }
    for(unsigned bad=1;bad<=13;bad++){
        graph_fixture(1);activate(1);graph_handoff_fault=bad;
        assert(!graph_open()&&graph_handoff_hit&&r->uncertain&&r->error==PGCD_CLOCK&&
            leaf_arches==graph_handoff_arches&&!r->map_guard[0].fp.restored&&!r->map_guard[0].left&&
            r->map_guard[0].unknown&&r->map[0].status==0&&r->map[0].issued==1&&r->map[0].returned==1);
        if(bad==8)graph_temporal_raw(argv[2],".handoff-zero");checks++;
    }
#endif
#if defined(PCMG_SUBSET_ONLY)
    const char*scope="subset";
#elif defined(PCMG_NORMAL_ONLY)
    const char*scope="normal_and_max";
#elif defined(PCMG_TEMPORAL_ONLY)
    const char*scope="normal_max_and_temporal";
#else
    const char*scope="full";
#endif
    printf("{\"passed\":true,\"scope\":\"%s\",\"checks\":%u,\"SOFTWARE_only\":true,\"contexts\":6,\"existing_maps\":11,\"stored_graphs\":12,\"graph_bytes\":%zu,\"normal_ATs\":66,\"normal_clocks\":69,\"max256_ATs\":321,\"max256_clocks\":324,\"whole_power_constructor_executed\":false,\"ownership_or_first_call_qualification\":false}\n",scope,checks,sizeof(struct pcmg_result));
    free(original);free(arena);free(payload_data);free(log_data);free(graph_core);free(graph_pool);return 0;
}
#endif
