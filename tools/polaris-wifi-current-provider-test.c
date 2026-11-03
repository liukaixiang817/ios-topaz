/* Genuine six generic contexts/eleven existing Map calls, with explicit
 * SOFTWARE service/AT/FP/clock peers. Original provider/Core PE is inert DATA. */
#define POLARIS_CURRENT_PROVIDER_FIXTURE 1
#define POLARIS_CURRENT_GRAPH_FIXTURE_ONLY 1
#include "polaris-wifi-current-graph-test.c"
#include "uefi-wifi-current-provider.h"
static struct pcmi_result(*providers)[2];static struct pcmi_result*active_provider;
static struct pcmp_live*provider_parent;
static uint8_t*provider_original[3],*provider_image[3];
static unsigned provider_running,provider_ATs,provider_clocks,provider_calls;
static unsigned provider_mode,provider_point,provider_fault,provider_byte,provider_hit,provider_entry;
static unsigned provider_temporal,provider_temporal_slot,provider_temporal_hit;
static unsigned provider_handoff_fault,provider_handoff_hit,provider_handoff_arches;
static uint64_t provider_floor;
#if defined(POLARIS_CURRENT_TIMER_FIXTURE)
static int fixture_timer_minimum(const struct pgcd_context*,unsigned,uint64_t*);
#endif
#if defined(POLARIS_CURRENT_EVENT_FIXTURE)
static int fixture_event_capture(struct pcmp_live*,int(*)(struct ppli_at*));
static int fixture_event_minimum(const struct pgcd_context*,unsigned,uint64_t*);
#endif
static int provider_mutate(struct ppli_at*at,struct pgcd_arch*clock)
{
    unsigned point=at?provider_ATs:provider_clocks;
    if(!provider_running||provider_hit||!provider_fault||provider_mode!=(at?1u:2u)||provider_point!=point)return 1;
    provider_hit=1;
    switch(provider_fault){
    case 1:return 0;case 2:if(at)at->returned=0;else clock->cpu.el=8;break;
    case 3:*cpu_flag=1;break;case 4:provider_parent->r=(void*)8;break;
    case 5:provider_parent->caller_input=(void*)8;break;case 6:provider_parent->original_io.arch=0;break;
    case 7:active_provider->binding.parent.r=(void*)8;break;case 8:active_provider->binding.graph=(void*)8;break;
    case 9:active_graph->digest[0]^=1;break;case 10:provider_image[0][0x1000]^=1;break;
    case 11:put(core+0x1cdb0,1235,8);break;case 12:active_provider->arch_issued++;break;
    case 13:assert(clock);clock->cpu.ticks=active_provider->arch_returned?
        active_provider->clock[active_provider->arch_returned-1].raw.cpu.ticks-1:active_provider->binding.minimum-1;break;
    case 14:assert(clock);clock->cpu.ticks=active_provider->binding.opening+PGCD_FRESH_TICKS+1;break;
    case 15:put(core+0x1d1a8,pwfi_le(core+0x1d1a8,8)+16,8);break;
    case 16:provider_parent->r->final_arch.cpu.el=5;break;
    case 17:active_provider->parent_after.r=(void*)8;break;case 18:active_provider->reserved=1;break;
    case 19:c->record=(void*)8;break;case 20:active_provider->binding_digest[0]^=1;break;
    case 21:((uint8_t*)provider_parent)[provider_byte]^=1;break;
    case 22:((uint8_t*)active_provider)[provider_byte]^=1;break;
    case 23:put(core+0x1d1a8,pwfi_le(core+0x1d1a8,8)^16,8);put(core+0x1d1a8,pwfi_le(core+0x1d1a8,8)^16,8);break;
    case 24:((uint8_t*)active_graph)[provider_byte]^=1;break;
    default:assert(0);
    }return 1;
}
static int provider_page(struct ppli_at*a)
{int ok=graph_page(a);if(provider_running){provider_ATs++;if(!provider_mutate(a,0))return 0;}return ok;}
static int provider_arch(void*o,struct pgcd_arch*a)
{
    int ok=graph_arch(o,a);if(a->cpu.ticks<provider_floor)a->cpu.ticks=provider_floor;
    if(provider_running){provider_clocks++;if(!provider_mutate(0,a))return 0;}
    else if(!graph_running&&provider_temporal&&!provider_temporal_hit&&active_provider&&active_provider->complete&&
        active_provider->binding.graph==active_graph&&active_graph->binding.slot==provider_temporal_slot){
        uint64_t last=active_provider->clock[active_provider->arch_returned-1].raw.cpu.ticks;
        provider_temporal_hit=1;
        switch(provider_temporal){
        case 1:a->cpu.ticks=last-1;break;case 2:a->cpu.ticks=active_provider->binding.minimum;break;
        case 3:a->cpu.ticks=last;break;case 4:a->cpu.ticks=last+1;break;
        case 5:provider_floor=a->cpu.ticks=active_provider->binding.opening+PGCD_FRESH_TICKS;break;
        case 6:a->cpu.ticks=active_provider->binding.opening+PGCD_FRESH_TICKS+1;break;
        case 7:a->cpu.ticks=UINT64_MAX;break;default:assert(0);
        }
    }return ok;
}
static int fixture_provider_capture(struct pcmp_live*parent,int(*read_page)(struct ppli_at*))
{
    assert(read_page==provider_page);provider_running=1;provider_ATs=provider_clocks=0;provider_calls++;
    provider_parent=parent;active_provider=&providers[active_route][parent->r->slot];
    struct pcmp_route selected[6];memcpy(selected,routes,sizeof(selected));unsigned count=6;
    struct pcmi_result(*out)[2]=providers;
    switch(provider_entry){
    case 0:break;case 1:count--;break;case 2:parent->r=(void*)8;break;case 3:out=(void*)8;break;
    case 4:out=(void*)((uintptr_t)parent->r-active_route*sizeof(*providers));break;
    case 5:out=(void*)((uintptr_t)cpu_flag-active_route*sizeof(*providers));break;
    case 6:selected[active_route].context=(void*)8;break;case 7:selected[active_route].source=(void*)8;break;
    case 8:active_graph->complete=0;break;case 9:active_graph->digest[0]^=1;break;
    case 10:active_provider->reserved=1;break;
    case 11:((uint8_t*)active_graph)[provider_byte]=1;break;default:assert(0);
    }
    int ok=pcmi_route_capture(selected,count,out,graphs,parent,read_page);provider_running=0;
#if defined(POLARIS_CURRENT_EVENT_FIXTURE)
    if(ok)ok=fixture_event_capture(parent,read_page);
#endif
    return ok;
}
static int fixture_provider_minimum(const struct pgcd_context*caller,unsigned slot,uint64_t*out)
{
    if(provider_handoff_fault&&!provider_handoff_hit){
        struct pcmi_result*p=&providers[active_route][slot];struct pbgi_clock*last=&p->clock[p->arch_returned-1];
        provider_handoff_hit=1;provider_handoff_arches=leaf_arches;
        /* Explicit negative SOFTWARE mutations after genuine capture, not
         * a constructed successful context/owner or firmware observation. */
        switch(provider_handoff_fault){
        case 1:p->complete=0;break;case 2:p->unknown=1;break;
        case 3:p->path.attempted=0;break;case 4:p->path.complete=0;break;case 5:p->path.finalized=1;break;
        case 6:p->hash_count[0]=0;break;case 7:p->hash_failed[1]=1;break;case 8:p->AT_count=PCMI_AT_MAX+1;break;
        case 9:p->arch_returned=0;break;case 10:p->arch_returned=PCMI_CLOCK_MAX+1;break;case 11:p->arch_issued--;break;
        case 12:last->returned=0;break;case 13:last->native[1]=1;break;case 14:last->raw.cpu.ticks=0;break;
        case 15:last->raw.cpu.ticks=p->binding.minimum-1;break;
        case 16:last->raw.cpu.ticks=p->binding.opening+PGCD_FRESH_TICKS+1;break;
        case 17:last->raw.cpu.ticks=UINT64_MAX;break;case 18:p->binding.graph=(void*)8;break;
        case 19:p->parent_after.r=(void*)8;break;case 20:p->digest[0]^=1;break;
        case 21:((uint8_t*)active_graph)[provider_byte]^=1;break;
        case 22:((uint8_t*)p)[provider_byte]^=1;break;default:assert(0);
        }
        if(provider_handoff_fault<20)ppli_sha(p,offsetof(struct pcmi_result,digest),p->digest);
    }
#if defined(POLARIS_CURRENT_EVENT_FIXTURE)
    return fixture_event_minimum(caller,slot,out);
#elif defined(POLARIS_CURRENT_TIMER_FIXTURE)
    return fixture_timer_minimum(caller,slot,out);
#else
    return pcmi_route_minimum(routes,6,graphs,providers,caller,slot,out);
#endif
}
static void provider_fixture(unsigned gcd_count,unsigned handlers,unsigned v3)
{
    graph_fixture(gcd_count);providers=(void*)(arena+0xe00000);
    assert((uint8_t*)providers+6*sizeof(*providers)<arena+fixture_image_bytes);memset(providers,0,6*sizeof(*providers));
    unsigned offset=0x20000;
    for(unsigned k=0;k<3;k++){
        const struct pwmc_irq_binding*b=&pwmc_irq_bindings[k];provider_image[k]=graph_pool+offset;offset+=(unsigned)b->bytes;
        assert(offset<=0x3c000);memcpy(provider_image[k],provider_original[k],b->bytes);
        for(unsigned j=0;j<b->reloc_count;j++){unsigned at=b->relocations[j];put(provider_image[k]+at,pwfi_le(provider_image[k]+at,8)+(uintptr_t)provider_image[k],8);}
        put(provider_image[k]+b->imagebase,(uintptr_t)provider_image[k],8);
    }
    uint64_t t=(uintptr_t)provider_image[0],g=(uintptr_t)provider_image[1],cpu=(uintptr_t)provider_image[2];
    uint64_t array=(uintptr_t)graph_pool+(handlers==1020?0x3dff0:0x3d100);
    put(core+0x1cb80,t+0x2038,8);put(core+0x1c8f8,cpu+0x53d8,8);
    put(provider_image[0]+0x2058,1,8);put(provider_image[0]+0x2068,(uintptr_t)core+0x1b800,8);
    put(provider_image[0]+0x2070,g+(v3?0x30e0:0x30b8),8);put(provider_image[0]+0x2078,(uintptr_t)s,8);
    put(provider_image[0]+0x2088,(uintptr_t)core+0xcbf8,8);put(provider_image[0]+0x2090,10000,8);put(provider_image[0]+0x2098,19200,8);
    put(provider_image[1]+0x3110,(uintptr_t)core+0x1b800,8);put(provider_image[1]+0x3120,array,8);
    put(provider_image[1]+0x3128,(uintptr_t)s,8);put(provider_image[1]+0x3150,handlers,8);
    put(provider_image[2]+0x5420,(uintptr_t)core+0x1b800,8);put(provider_image[2]+0x5438,g+(v3?0x1acc:0x1294),8);
    put(provider_image[2]+0x5450,(uintptr_t)s,8);
    for(unsigned k=0;k<handlers;k++)put((void*)(uintptr_t)(array+8*k),(k==18||k==19||k==26||k==29)?t+0x10c8:0,8);
    original_io.arch=provider_arch;current_fixture_page=provider_page;
    for(unsigned n=0;n<6;n++)routes[n].context->io.arch=provider_arch;
    active_provider=0;provider_parent=0;provider_running=provider_calls=provider_ATs=provider_clocks=0;
    provider_mode=provider_point=provider_fault=provider_byte=provider_hit=provider_entry=0;
    provider_temporal=provider_temporal_slot=provider_temporal_hit=0;provider_floor=0;
    provider_handoff_fault=provider_handoff_hit=provider_handoff_arches=0;
}
static void provider_pair_raw(const char*base,const char*suffix)
{char name[4096];int n=snprintf(name,sizeof(name),"%s%s",base,suffix);assert(n>0&&(size_t)n<sizeof(name));FILE*f=fopen(name,"wb");
 assert(f&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&fwrite(cur,1,sizeof(*cur),f)==sizeof(*cur)&&
 fwrite(active_graph,1,sizeof(*active_graph),f)==sizeof(*active_graph)&&fwrite(active_provider,1,sizeof(*active_provider),f)==sizeof(*active_provider)&&!fclose(f));}
#ifndef POLARIS_CURRENT_PROVIDER_FIXTURE_ONLY
int main(int argc,char**argv)
{
    assert(argc==6&&!posix_memalign((void**)&arena,4096,0x1001000));
    assert(!posix_memalign((void**)&payload_data,4096,4096)&&!posix_memalign((void**)&log_data,4096,4096));
    assert(!posix_memalign((void**)&graph_core,4096,PGCI_IMAGE_BYTES)&&!posix_memalign((void**)&graph_pool,4096,0x40000));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");
    assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    for(unsigned k=0;k<3;k++){provider_original[k]=malloc(pwmc_irq_bindings[k].bytes);f=fopen(argv[2+k],"rb");
        assert(provider_original[k]&&f&&fread(provider_original[k],1,pwmc_irq_bindings[k].bytes,f)==pwmc_irq_bindings[k].bytes&&!fclose(f));}
    unsigned checks=0;provider_fixture(1,64,1);
    for(unsigned pass=0;pass<6;pass++){
        unsigned n=pass<5?pass+1:0;activate(n);
        if(n){assert(graph_open());if(n<5)assert(pgcd_map_read(c,1));}
        else {for(unsigned k=0;k<4;k++){const struct pgcd_observation*q=0;assert(pgcd_query_page(c,pgcd_pages[k],&q));}assert(pgcd_finish(c));}
        for(unsigned k=0;k<(n==5?1u:2u);k++){
            const struct pcmi_result*p=&providers[n][k];assert(p->complete&&!p->unknown&&!p->error&&p->path.complete&&p->parent_copied==1);
            assert(p->binding.graph==&graphs[n][k]&&p->binding.parent.input.context==c&&p->binding.opening==r->before.cpu.ticks);
            assert(p->binding.minimum==graphs[n][k].graph.clock[graphs[n][k].graph.arch_returned-1].raw.cpu.ticks);
            assert(p->AT_count==20&&p->arch_issued==23&&p->arch_returned==23&&p->hash_count[0]==5&&p->hash_count[1]==5);
            assert(!p->path.finalized&&pwmc_zero(p->path.regs,sizeof(p->path.regs))&&p->path.handler_count==64);
            assert(r->map_guard[k].after.cpu.ticks>=p->clock[22].raw.cpu.ticks);checks++;
        }
    }
    assert(leaf_maps==11&&provider_calls==11&&pwmc_zero(&providers[5][1],sizeof(providers[5][1])));checks++;
    f=fopen(argv[5],"wb");assert(f);
    for(unsigned n=0;n<6;n++){assert(fwrite(routes[n].source,1,sizeof(*r),f)==sizeof(*r));
        assert(fwrite(routes[n].frames,sizeof(*cur),2,f)==2&&fwrite(graphs[n],sizeof(*active_graph),2,f)==2&&fwrite(providers[n],sizeof(*active_provider),2,f)==2);}
    assert(!fclose(f));
    for(unsigned v3=0;v3<2;v3++){
        provider_fixture(256,1020,v3);activate(1);assert(graph_open()&&active_provider->complete&&active_provider->path.handler_count==1020&&
            active_provider->path.array_AT_count==3&&provider_ATs==22&&provider_clocks==25);checks++;
        provider_pair_raw(argv[5],v3?".max-v3":".max-v2");
    }
#if !defined(PCMI_NORMAL_ONLY) && !defined(PCMI_HANDOFF_ONLY)
    /* The old graph prefix digest excludes aligned trailing RAW padding.
     * Exercise every such byte at every real provider leaf, and cold entry.
     * Preserve the damaged graph; never clear it to obtain logical success. */
    const unsigned tail_start=offsetof(struct pcmg_result,digest)+sizeof(active_graph->digest);
    assert(tail_start==310472&&sizeof(*active_graph)-tail_start==8);
    for(unsigned byte=tail_start;byte<sizeof(*active_graph);byte++){
        provider_fixture(1,64,1);activate(1);provider_entry=11;provider_byte=byte;
        assert(!graph_open()&&graph_stopped&&cur->error==7&&((uint8_t*)active_graph)[byte]==1&&
            !active_provider->attempted&&!provider_ATs&&!provider_clocks&&!r->map_guard[0].fp.restored);checks++;
        for(unsigned mode=1;mode<=2;mode++)for(unsigned point=1;point<=(mode==1?20u:23u);point++){
#if defined(PCMI_GRAPH_TAIL_SUBSET)
            if(point!=1&&point!=(mode==1?20u:23u))continue;
#endif
            provider_fixture(1,64,1);activate(1);provider_mode=mode;provider_point=point;provider_fault=24;provider_byte=byte;
            assert(!graph_open()&&provider_hit&&graph_stopped&&cur->error==7&&active_provider->unknown&&
                !active_provider->complete&&!r->map_guard[0].fp.restored&&((uint8_t*)active_graph)[byte]==1&&
                cur->call.map.status==0&&cur->call.map.issued==1&&cur->call.map.returned==1);
            uint8_t hash[32];ppli_sha(active_graph,offsetof(struct pcmg_result,digest),hash);
            assert(pgcd_equal(hash,active_graph->digest,32));
            if(mode==1){const struct ppli_at*a=&active_provider->AT[point-1];
                assert(provider_ATs==point&&active_provider->AT_count==point-1&&a->issued==1&&a->returned==1&&
                    a->native_issued==1&&a->native_returned==1);}
            else {const struct pbgi_clock*a=&active_provider->clock[point-1];
                assert(provider_clocks==point&&active_provider->arch_issued==point&&active_provider->arch_returned==point-1&&
                    a->issued==1&&!a->returned&&a->native_issued==1&&a->native_returned==1);}
            if(mode==2&&point==1&&byte==tail_start)provider_pair_raw(argv[5],".graph-tail-refused");
            checks++;
        }
        provider_fixture(1,64,1);activate(1);provider_handoff_fault=21;provider_byte=byte;
        assert(!graph_open()&&provider_handoff_hit&&leaf_arches==provider_handoff_arches&&active_provider->complete&&
            active_graph->complete&&((uint8_t*)active_graph)[byte]==1&&r->uncertain&&!r->map_guard[0].fp.restored&&
            !r->map_guard[0].left&&r->map[0].status==0&&r->map[0].issued==1&&r->map[0].returned==1);
        if(byte==tail_start)provider_pair_raw(argv[5],".graph-tail-handoff");checks++;
    }
    /* Own provider padding was already sealed across active callbacks. It
     * must remain closed when the completed DATA minimum is handed out too. */
    const unsigned own_tail=offsetof(struct pcmi_result,digest)+sizeof(active_provider->digest);
    assert(own_tail==20452&&sizeof(*active_provider)-own_tail==4);
    for(unsigned byte=own_tail;byte<sizeof(*active_provider);byte++){
        provider_fixture(1,64,1);activate(1);provider_handoff_fault=22;provider_byte=byte;
        assert(!graph_open()&&provider_handoff_hit&&leaf_arches==provider_handoff_arches&&active_provider->complete&&
            ((uint8_t*)active_provider)[byte]==1&&r->uncertain&&!r->map_guard[0].fp.restored&&!r->map_guard[0].left&&
            r->map[0].status==0&&r->map[0].issued==1&&r->map[0].returned==1);
        if(byte==own_tail)provider_pair_raw(argv[5],".provider-tail-handoff");checks++;
    }
#endif
#if !defined(PCMI_NORMAL_ONLY) && !defined(PCMI_HANDOFF_ONLY) && !defined(PCMI_GRAPH_TAIL_ONLY)
    for(unsigned bad=1;bad<=10;bad++){
        provider_fixture(1,64,1);activate(1);provider_entry=bad;
        assert(!graph_open()&&graph_stopped&&cur->error==7&&!r->map_guard[0].fp.restored&&!provider_ATs&&!provider_clocks);
        if(bad==10)assert(active_provider->reserved==1&&!active_provider->attempted);checks++;
    }
    for(unsigned mode=1;mode<=2;mode++)for(unsigned bad=1;bad<=20;bad++){
        if(mode==1&&(bad==13||bad==14))continue;
        for(unsigned point=1;point<=(mode==1?20u:23u);point++){
#if defined(PCMI_SUBSET_ONLY)
            if(point!=1&&point!=(mode==1?20u:23u))continue;
#endif
            provider_fixture(1,64,1);activate(1);provider_mode=mode;provider_fault=bad;provider_point=point;
            assert(!graph_open()&&provider_hit&&graph_stopped&&cur->error==7&&active_provider->unknown&&!active_provider->complete);
            assert(!r->map_guard[0].fp.restored&&cur->call.map.status==0&&cur->call.map.issued==1&&cur->call.map.returned==1);
            if(mode==2&&point==1&&(bad==4||bad==9))provider_pair_raw(argv[5],bad==4?".parent-refused":".graph-refused");checks++;
        }
        fprintf(stderr,"PROGRESS provider mode%u fault%u cases%u\n",mode,bad,checks);
    }
    /* Reuse the qualified whole-frame seal/equality readers. Exercise actual
     * caller pointer/control boundaries here, rather than repeating their
     * older every-byte leaf tests at a new call site. */
    const unsigned parent_fields[]={0,7,8,15,16,23,32,39,88,95,120,127,128,135,136,143,144,151,152,159,
        160,167,168,175,176,183,184,191,192,199,200,207,208,215,216,247,248,279,280,283,284,287,
        288,291,292,295,296,299,300,303};
    for(unsigned mode=1;mode<=2;mode++)for(unsigned field=0;field<sizeof(parent_fields)/sizeof(parent_fields[0]);field++){
        unsigned byte=parent_fields[field];
#if defined(PCMI_SUBSET_ONLY)
        if(byte!=0&&byte!=sizeof(struct pcmp_live)-1)continue;
#endif
        provider_fixture(1,64,1);activate(1);provider_mode=mode;provider_point=1;provider_fault=21;provider_byte=byte;
        assert(!graph_open()&&provider_hit&&graph_stopped&&active_provider->unknown&&cur->error==7);checks++;
    }
    const unsigned fields[]={0,7,8,15,135,136,207,208,215,216,247,248,311,312,319,320,327,328,335,336,367,368,399,
        offsetof(struct pcmi_result,binding_digest),offsetof(struct pcmi_result,path),offsetof(struct pcmi_result,AT),
        offsetof(struct pcmi_result,clock),offsetof(struct pcmi_result,Core_hash),offsetof(struct pcmi_result,hash_count),
        offsetof(struct pcmi_result,parent_after),offsetof(struct pcmi_result,attempted),offsetof(struct pcmi_result,complete),
        offsetof(struct pcmi_result,unknown),offsetof(struct pcmi_result,error),offsetof(struct pcmi_result,AT_count),
        offsetof(struct pcmi_result,arch_issued),offsetof(struct pcmi_result,arch_returned),offsetof(struct pcmi_result,parent_copied),
        offsetof(struct pcmi_result,reserved),offsetof(struct pcmi_result,digest),sizeof(struct pcmi_result)-1};
    for(unsigned mode=1;mode<=2;mode++)for(unsigned k=0;k<sizeof(fields)/sizeof(fields[0]);k++){
        provider_fixture(1,64,1);activate(1);provider_mode=mode;provider_point=1;provider_fault=22;provider_byte=fields[k];
        assert(!graph_open()&&provider_hit&&graph_stopped&&active_provider->unknown&&cur->error==7);checks++;
    }
    for(unsigned n=0;n<6;n++)for(unsigned slot=0;slot<(n==5?1u:2u);slot++)for(unsigned bad=1;bad<=7;bad++){
        provider_fixture(1,64,1);activate(n);provider_temporal=bad;provider_temporal_slot=slot;
        int ok=graph_temporal_run(n,slot),expected=bad>=3&&bad<=5;
        assert(ok==expected&&provider_temporal_hit&&active_provider->complete&&cur->complete);
        if(!expected)assert(r->uncertain&&!r->map_guard[slot].fp.restored&&!r->map_guard[slot].left);
        if(n==1&&!slot&&(bad==1||bad==3))provider_pair_raw(argv[5],bad==1?".temporal-refused":".temporal-equal");checks++;
    }
    provider_fixture(1,64,1);activate(1);provider_mode=2;provider_point=23;provider_fault=23;
    assert(graph_open()&&provider_hit&&active_provider->complete&&!active_provider->unknown);checks++;
#endif
#if !defined(PCMI_NORMAL_ONLY) && !defined(PCMI_GRAPH_TAIL_ONLY)
    for(unsigned bad=1;bad<=20;bad++){
        provider_fixture(1,64,1);activate(1);provider_handoff_fault=bad;
        assert(!graph_open()&&provider_handoff_hit&&leaf_arches==provider_handoff_arches&&r->uncertain&&
            !r->map_guard[0].fp.restored&&!r->map_guard[0].left&&r->map[0].status==0&&r->map[0].issued==1&&r->map[0].returned==1);
        if(bad==14)provider_pair_raw(argv[5],".handoff-zero");checks++;
    }
#endif
    printf("{\"passed\":true,\"checks\":%u,\"SOFTWARE_only\":true,\"contexts\":6,\"existing_maps\":11,\"provider_bytes\":%zu,\"binding_bytes\":%zu,\"live_bytes\":%zu,\"path_offset\":%zu,\"AT_offset\":%zu,\"clock_offset\":%zu,\"parent_after_offset\":%zu,\"digest_offset\":%zu,\"normal_ATs\":20,\"normal_clocks\":23,\"max_ATs\":22,\"max_clocks\":25,\"original_PE_or_whole_constructor_executed\":false,\"owner_IRQ_ABA_or_lease_qualification\":false}\n",checks,sizeof(struct pcmi_result),sizeof(struct pcmi_binding),sizeof(struct pcmi_live),offsetof(struct pcmi_result,path),offsetof(struct pcmi_result,AT),offsetof(struct pcmi_result,clock),offsetof(struct pcmi_result,parent_after),offsetof(struct pcmi_result,digest));
    return 0;
}
#endif
