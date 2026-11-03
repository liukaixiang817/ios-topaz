/* Real six-route active Map caller; all service/AT/arch/MRS/FP are peers.
 * Original PE bytes are DATA only. No native or whole constructor executes. */
#define POLARIS_CURRENT_EVENT_FIXTURE 1
#define POLARIS_CURRENT_TIMER_FIXTURE_ONLY 1
#include "polaris-wifi-current-timer-test.c"
#include "uefi-wifi-current-events.h"
static struct pcme_result(*events)[2],*active_event;
static struct pcmp_live*event_parent;
static unsigned event_running,event_calls,event_ATs,event_clocks,event_mode,event_point,event_fault,event_byte,event_hit;
static unsigned event_temporal,event_temporal_slot,event_temporal_hit,event_handoff,event_handoff_hit,event_entry;
static unsigned event_image_protection;
static uint64_t event_floor;
static int event_mutate(struct ppli_at*a,struct pgcd_arch*clock)
{
    if(!event_running||event_hit||!event_fault||event_mode!=(a?1u:2u)||event_point!=(a?event_ATs:event_clocks))return 1;
    event_hit=1;
    switch(event_fault){
    case 1:return 0;case 2:if(a)a->returned=0;else clock->cpu.el=8;break;
    case 3:*cpu_flag=1;break;case 4:event_parent->r=(void*)8;break;
    case 5:active_graph->digest[0]^=1;break;case 6:active_provider->digest[0]^=1;break;
    case 7:active_timer->digest[0]^=1;break;case 8:put(core+0x1cdb0,1235,8);break;
    case 9:put(core+0x1c368,8,8);break;case 10:((uint8_t*)active_event)[event_byte]^=1;break;
    case 11:assert(clock);clock->cpu.ticks=active_event->arch_returned?
        active_event->clock[active_event->arch_returned-1].raw.cpu.ticks-1:active_event->binding.minimum-1;break;
    case 12:assert(clock);clock->cpu.ticks=active_event->binding.opening+PGCD_FRESH_TICKS+1;break;
    case 13:provider_image[0][0x1000]^=1;break;
    case 14:((uint8_t*)event_parent)[event_byte]^=1;break;
    case 15:((uint8_t*)(uintptr_t)active_event->binding.live_address)[event_byte]^=1;break;
    case 16:put(core+0x1c368,pwfi_le(core+0x1c368,8)^16,8);put(core+0x1c368,pwfi_le(core+0x1c368,8)^16,8);break;
    case 17:assert(clock);clock->cpu.el=8;assert(!mprotect(graph_core,core_mapping_bytes,PROT_NONE)&&!mprotect(graph_pool,0x40000,PROT_NONE));break;
    default:assert(0);
    }return 1;
}
static int event_page(struct ppli_at*a)
{int ok=provider_page(a);if(event_running){event_ATs++;if(!event_mutate(a,0))return 0;}return ok;}
static int event_arch(void*opaque,struct pgcd_arch*a)
{
    int ok=timer_arch(opaque,a);if(a->cpu.ticks<event_floor)a->cpu.ticks=event_floor;
    if(event_running){event_clocks++;if(!event_mutate(0,a))return 0;}
    else if(event_temporal&&!event_temporal_hit&&active_event&&active_event->complete&&
        active_event->binding.parent.r==cur&&cur->slot==event_temporal_slot){
        uint64_t last=active_event->clock[active_event->arch_returned-1].raw.cpu.ticks;event_temporal_hit=1;
        switch(event_temporal){case 1:a->cpu.ticks=last-1;break;case 2:a->cpu.ticks=active_event->binding.minimum;break;
        case 3:a->cpu.ticks=last;break;case 4:a->cpu.ticks=last+1;break;
        case 5:event_floor=a->cpu.ticks=active_event->binding.opening+PGCD_FRESH_TICKS;break;
        case 6:a->cpu.ticks=active_event->binding.opening+PGCD_FRESH_TICKS+1;break;
        case 7:a->cpu.ticks=UINT64_MAX;break;default:assert(0);}
    }return ok;
}
static int fixture_event_capture(struct pcmp_live*parent,int(*read_page)(struct ppli_at*))
{
    assert(read_page==provider_page);event_calls++;event_parent=parent;active_event=&events[active_route][parent->r->slot];
    event_running=1;event_ATs=event_clocks=0;struct pcme_result(*out)[2]=events;
    const struct pcmg_result(*gs)[2]=graphs;const struct pcmi_result(*ps)[2]=providers;const struct pcmt_result(*ts)[2]=timers;
    switch(event_entry){case 0:break;case 1:out=(void*)8;break;case 2:out=(void*)graphs;break;
    case 3:active_event->reserved=1;break;case 4:active_provider->complete=0;break;
    case 5:active_timer->complete=0;break;case 6:parent->r=(void*)8;break;
    case 7:gs=(void*)8;break;case 8:ps=(void*)8;break;case 9:ts=(void*)8;break;case 10:out=(void*)((uint8_t*)out+1);break;
    default:assert(0);}
    int ok=pcme_route_capture(routes,6,out,gs,ps,ts,parent,event_page);event_running=0;return ok;
}
static int fixture_event_minimum(const struct pgcd_context*c,unsigned slot,uint64_t*out)
{
    if(event_handoff&&!event_handoff_hit){
        struct pcme_result*e=&events[active_route][slot];event_handoff_hit=1;
        switch(event_handoff){case 1:e->complete=0;break;case 2:e->unknown=1;break;case 3:e->reserved=1;break;
        case 4:e->arch_returned=0;break;case 5:e->arch_issued--;break;case 6:e->binding.provider=(void*)8;break;
        case 7:e->clock[e->arch_returned-1].raw.cpu.ticks=0;break;case 8:e->clock[e->arch_returned-1].native[1]=1;break;
        case 9:e->clock[e->arch_returned-1].returned=0;break;case 10:e->binding.minimum--;break;
        case 11:e->parent_after.r=(void*)8;break;case 12:e->control_after.page=0;break;
        case 13:e->control_after.r=(void*)8;break;case 14:e->hash_count[1][3]=0;break;
        case 15:e->hash_failed[1][0]=1;break;case 16:e->binding_digest[0]^=1;break;case 17:e->digest[0]^=1;break;
        case 18:e->events.count=PWMC_EVENT_MAX+1;break;case 19:e->timers.count=PWMC_TIMER_MAX+1;break;
        case 20:((uint8_t*)e)[sizeof(*e)-1]^=1;break;case 21:e->AT_status[0]=0;break;
        case 22:e->arch_status[e->arch_returned-1]=0;break;case 23:e->AT_issued=0;break;case 24:e->AT_returned=0;break;
        case 25:e->reserved2=1;break;case 26:e->control_copied=0;break;default:assert(0);}
        if(event_handoff!=16)ppli_sha(&e->binding,sizeof(e->binding),e->binding_digest);
        if(event_handoff!=17&&event_handoff!=20)ppli_sha(e,offsetof(struct pcme_result,digest),e->digest);
    }
    size_t page=(size_t)sysconf(_SC_PAGESIZE);void*descriptor=(void*)((uintptr_t)self&~(page-1));
    if(event_image_protection)assert(!mprotect(descriptor,page,PROT_NONE));
    int ok=pcme_route_minimum(routes,6,graphs,providers,timers,events,c,slot,out);
    if(event_image_protection)assert(!mprotect(descriptor,page,PROT_READ|PROT_WRITE));
    return ok;
}
static void event_install(unsigned count,unsigned timer_count,unsigned overflow)
{
    uint64_t eh=(uintptr_t)core+0x1c368,th=(uintptr_t)core+0x1c3f0;
    for(unsigned k=0;k<3;k++){unsigned at=k==0?0x1c350:k==1?0x1c3d8:0x1c400;
        put(core+at,k==2?30:31,8);put(core+at+8,4,8);put(core+at+16,1,4);}
    memcpy(core+0x1b130,&pwmc_map_change_group,16);
    uint64_t checker=count?(uintptr_t)graph_pool+0x6fe0:0;
    put(core+0x1cbc8,checker,8);put(core+0x1c368,count?checker+16:eh,8);
    put(core+0x1c370,count?(count==1?checker+16:(uintptr_t)graph_pool+0x7100+128*(count-2)+16):eh,8);
    for(unsigned k=0;k<count;k++){
        uint64_t at=k?(uintptr_t)graph_pool+0x7100+128*(k-1):checker;
        uint64_t next=k+1==count?(overflow==1?8:eh):(uintptr_t)graph_pool+0x7100+128*k+16;
        uint64_t prior=k?(k==1?checker+16:at-128+16):eh;
        uint8_t*n=(void*)(uintptr_t)at;memset(n,0,k?88:184);put(n,0x746e7665,8);put(n+8,k?0x100:0x200,4);
        put(n+16,next,8);put(n+24,prior,8);put(n+32,k?8:30,8);put(n+40,(uintptr_t)core+0xcb24,8);
    }
    put(core+0x1c3f0,timer_count?(uintptr_t)graph_pool+0xc000+152:th,8);
    put(core+0x1c3f8,timer_count?(uintptr_t)graph_pool+0xc000+256*(timer_count-1)+152:th,8);
    for(unsigned k=0;k<timer_count;k++){
        uint8_t*n=graph_pool+0xc000+256*k;memset(n,0,184);put(n,0x746e7665,8);put(n+8,0x80000100,4);
        put(n+32,k&1?16:8,8);put(n+40,(uintptr_t)core+0xcb24,8);
        put(n+152,k+1==timer_count?(overflow==2?8:th):(uintptr_t)n+256+152,8);
        put(n+160,k?(uintptr_t)n-256+152:th,8);put(n+168,10000+k,8);
    }
}
static void event_fixture(unsigned gcd,unsigned handlers,unsigned v3,unsigned count,unsigned timer_count,unsigned overflow)
{
    timer_fixture(gcd,handlers,v3);events=(void*)(arena+0x280000);memset(events,0,6*sizeof(*events));
    assert((uint8_t*)events+6*sizeof(*events)<arena+0x400000);event_install(count,timer_count,overflow);
    original_io.arch=event_arch;for(unsigned n=0;n<6;n++)routes[n].context->io.arch=event_arch;
    event_running=event_calls=event_ATs=event_clocks=event_mode=event_point=event_fault=event_byte=event_hit=0;
    event_temporal=event_temporal_slot=event_temporal_hit=event_handoff=event_handoff_hit=event_entry=0;event_floor=0;active_event=0;
    event_image_protection=0;
}
static void event_raw(const char*base,const char*suffix)
{char name[4096];int n=snprintf(name,sizeof(name),"%s%s",base,suffix);assert(n>0&&(size_t)n<sizeof(name));FILE*f=fopen(name,"wb");
 assert(f&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&fwrite(cur,1,sizeof(*cur),f)==sizeof(*cur)&&
 fwrite(active_graph,1,sizeof(*active_graph),f)==sizeof(*active_graph)&&fwrite(active_provider,1,sizeof(*active_provider),f)==sizeof(*active_provider)&&
 fwrite(active_timer,1,sizeof(*active_timer),f)==sizeof(*active_timer)&&fwrite(active_event,1,sizeof(*active_event),f)==sizeof(*active_event)&&!fclose(f));}
int main(int argc,char**argv)
{
    assert(argc==6);timer_memory();original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");
    assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    for(unsigned k=0;k<3;k++){provider_original[k]=malloc(pwmc_irq_bindings[k].bytes);f=fopen(argv[2+k],"rb");
        assert(provider_original[k]&&f&&fread(provider_original[k],1,pwmc_irq_bindings[k].bytes,f)==pwmc_irq_bindings[k].bytes&&!fclose(f));}
    unsigned checks=0;event_fixture(1,64,1,1,3,0);
    for(unsigned pass=0;pass<6;pass++){
        unsigned n=pass<5?pass+1:0;activate(n);
        if(n){if(!graph_open()){event_raw(argv[5],".unexpected-normal");fprintf(stderr,"NORMAL route%u err outer%u map%u event%u AT%u clocks%u\n",n,r->error,cur->error,active_event?active_event->error:0,event_ATs,event_clocks);assert(0);}if(n<5)assert(pgcd_map_read(c,1));}
        else {for(unsigned k=0;k<4;k++){const struct pgcd_observation*q=0;assert(pgcd_query_page(c,pgcd_pages[k],&q));}assert(pgcd_finish(c));}
        for(unsigned slot=0;slot<(n==5?1u:2u);slot++){
            const struct pcme_result*e=&events[n][slot];assert(e->complete&&!e->unknown&&!e->error&&e->events.count==1&&e->timers.count==3&&
                e->AT_count==7&&e->arch_returned==9&&r->map_guard[slot].fp.restored&&e->parent_copied&&e->control_copied);checks++;
        }
    }
    assert(event_calls==11&&timer_calls==11&&timer_reads==22&&leaf_maps==11&&pwmc_zero(&events[5][1],sizeof(events[5][1])));checks++;
    f=fopen(argv[5],"wb");assert(f);for(unsigned n=0;n<6;n++)assert(fwrite(routes[n].source,1,sizeof(*r),f)==sizeof(*r)&&
        fwrite(routes[n].frames,sizeof(*cur),2,f)==2&&fwrite(graphs[n],sizeof(*active_graph),2,f)==2&&
        fwrite(providers[n],sizeof(*active_provider),2,f)==2&&fwrite(timers[n],sizeof(*active_timer),2,f)==2&&fwrite(events[n],sizeof(*active_event),2,f)==2);
    assert(!fclose(f));
    for(unsigned v3=0;v3<2;v3++){
        event_fixture(256,1020,v3,128,32,0);activate(1);assert(graph_open()&&active_event->complete&&active_event->events.count==128&&
            active_event->timers.count==32&&event_ATs==163&&event_clocks==165);event_raw(argv[5],v3?".max-v3":".max-v2");checks++;
    }
#if !defined(PCME_NORMAL_ONLY)
    fprintf(stderr,"{\"partial_stage\":\"normal_and_max\",\"checks_completed\":%u}\n",checks);
    for(unsigned n=0;n<6;n++)for(unsigned slot=0;slot<(n==5?1u:2u);slot++)for(unsigned value=1;value<=7;value++){
        event_fixture(1,64,1,1,3,0);activate(n);event_temporal=value;event_temporal_slot=slot;int ok=1;
        if(n){ok=graph_open();if(ok&&slot)ok=pgcd_map_read(c,1);}else {if(setjmp(graph_terminal))ok=0;
            else {for(unsigned k=0;k<4;k++){const struct pgcd_observation*q=0;if(!pgcd_query_page(c,pgcd_pages[k],&q)){ok=0;break;}}if(ok)ok=pgcd_finish(c);}}
        assert(event_temporal_hit&&ok==(value>=3&&value<=5));
        assert(active_event->complete&&!active_event->unknown&&cur->complete&&!cur->unknown);
        if(!ok)assert(r->uncertain&&r->map_guard[slot].unknown&&!r->map_guard[slot].fp.restored&&
            !r->map_guard[slot].left&&r->map[slot].status==0&&r->map[slot].issued==1&&r->map[slot].returned==1);
        if(n==1&&!slot&&value==1)event_raw(argv[5],".temporal-refused");checks++;
    }
    fprintf(stderr,"{\"partial_stage\":\"eleven_boundaries_temporal\",\"checks_completed\":%u}\n",checks);
#endif
#if !defined(PCME_NORMAL_ONLY) && !defined(PCME_TEMPORAL_ONLY)
#if !defined(PCME_CLOSING_ONLY)
    for(unsigned overflow=1;overflow<=2;overflow++){
        event_fixture(1,64,1,128,32,overflow);activate(1);assert(!graph_open()&&graph_stopped&&active_event->unknown&&!r->map_guard[0].fp.restored);
        assert(overflow==1?event_ATs==129:event_ATs==163);checks++;
    }
    event_fixture(1,64,1,0,0,0);activate(1);assert(graph_open()&&event_ATs==0&&event_clocks==2);checks++;
    for(unsigned bit=0;bit<5;bit++){
        event_fixture(1,64,1,1,3,0);activate(1);put(core+0x1dbc0,UINT64_C(1)<<bit,8);
        assert(!graph_open()&&graph_stopped&&active_event->events.pending==(UINT64_C(1)<<bit)&&
            timer_reads==2&&!event_ATs&&!r->map_guard[0].fp.restored);checks++;
    }
    for(unsigned bad=0;bad<8;bad++){
        event_fixture(1,64,1,1,3,0);activate(1);
        switch(bad){case 0:put(graph_pool+0x6fe0+176,1,8);break;case 1:put(graph_pool+0xc000+176,1,8);break;
        case 2:memcpy(graph_pool+0x6fe0+56,&pwmc_map_change_group,16);break;
        case 3:put(graph_pool+0x6fe0+40,8,8);break;case 4:put(graph_pool+0xc000+160,8,8);break;
        case 5:put(core+0x1c370,8,8);break;case 6:put(core+0x1cbc8,8,8);break;
        case 7:put(core+0x1c368,(uintptr_t)arena+0x200010,8);break;}
        assert(!graph_open()&&graph_stopped&&!r->map_guard[0].fp.restored);checks++;
    }
    for(unsigned bad=1;bad<=10;bad++){
        event_fixture(1,64,1,1,3,0);activate(1);event_entry=bad;assert(!graph_open()&&graph_stopped&&!event_ATs&&!event_clocks&&!r->map_guard[0].fp.restored);checks++;
    }
    for(unsigned mode=1;mode<=2;mode++)for(unsigned point=1;point<=(mode==1?7u:9u);point++)for(unsigned bad=1;bad<=13;bad++){
        if(bad==10||((bad==11||bad==12)&&mode==1))continue;
        event_fixture(1,64,1,1,3,0);activate(1);event_mode=mode;event_point=point;event_fault=bad;
        assert(!graph_open()&&event_hit&&graph_stopped&&active_event->unknown&&!r->map_guard[0].fp.restored);
        assert(cur->call.map.status==0&&cur->call.map.issued==1&&cur->call.map.returned==1);
        if(mode==1&&point==1&&bad==2){assert(active_event->AT_returned==1&&active_event->AT_status[0]==1);event_raw(argv[5],".partial");}
        if(point==1&&bad==1){assert(mode==1?(active_event->AT_returned==1&&!active_event->AT_status[0]):(active_event->arch_returned==1&&!active_event->arch_status[0]));event_raw(argv[5],mode==1?".AT-C-return0":".arch-C-return0");}
        if(mode==2&&point==1&&(bad==4||bad==5||bad==6))event_raw(argv[5],bad==4?".parent-refused":bad==5?".graph-source-refused":".provider-source-refused");
        if(mode==2&&point==9&&bad==13)event_raw(argv[5],".last-callback-code");checks++;
    }
    fprintf(stderr,"{\"partial_stage\":\"all_normal_AT_arch_fault_stages\",\"checks_completed\":%u}\n",checks);
    for(unsigned byte=0;byte<sizeof(struct pcme_live);byte++){
        event_fixture(1,64,1,1,3,0);activate(1);event_mode=2;event_point=1;event_fault=15;event_byte=byte;
        assert(!graph_open()&&event_hit&&graph_stopped&&active_event->unknown&&!r->map_guard[0].fp.restored);checks++;
    }
    fprintf(stderr,"{\"partial_stage\":\"actual_552_control_bytes\",\"checks_completed\":%u}\n",checks);
    for(unsigned byte=0;byte<sizeof(struct pcmp_live);byte++){
        event_fixture(1,64,1,1,3,0);activate(1);event_mode=1;event_point=1;event_fault=14;event_byte=byte;
        assert(!graph_open()&&event_hit&&graph_stopped&&active_event->unknown&&!r->map_guard[0].fp.restored);checks++;
    }
    fprintf(stderr,"{\"partial_stage\":\"actual_304_parent_bytes\",\"checks_completed\":%u}\n",checks);
    const unsigned fields[]={0,7,8,15,312,319,320,327,328,335,336,343,344,351,352,359,360,487,488,519,
        offsetof(struct pcme_result,events),offsetof(struct pcme_result,timers),offsetof(struct pcme_result,AT),
        offsetof(struct pcme_result,clock)+sizeof(struct pbgi_clock),offsetof(struct pcme_result,hashes),
        offsetof(struct pcme_result,hash_count),offsetof(struct pcme_result,hash_failed),offsetof(struct pcme_result,AT_status),
        offsetof(struct pcme_result,arch_status),offsetof(struct pcme_result,AT_issued),offsetof(struct pcme_result,AT_returned),offsetof(struct pcme_result,parent_after),
        offsetof(struct pcme_result,control_after),offsetof(struct pcme_result,attempted),offsetof(struct pcme_result,complete),
        offsetof(struct pcme_result,unknown),offsetof(struct pcme_result,error),offsetof(struct pcme_result,AT_count),
        offsetof(struct pcme_result,arch_issued),offsetof(struct pcme_result,arch_returned),offsetof(struct pcme_result,parent_copied),
        offsetof(struct pcme_result,reserved),offsetof(struct pcme_result,refusal_timer),offsetof(struct pcme_result,control_copied),
        offsetof(struct pcme_result,reserved2),offsetof(struct pcme_result,digest),sizeof(struct pcme_result)-1};
    for(unsigned mode=1;mode<=2;mode++)for(unsigned k=0;k<sizeof(fields)/sizeof(fields[0]);k++){
        event_fixture(1,64,1,1,3,0);activate(1);event_mode=mode;event_point=1;event_fault=10;event_byte=fields[k];
        assert(!graph_open()&&event_hit&&graph_stopped&&active_event->unknown&&!r->map_guard[0].fp.restored);checks++;
    }
#endif
    for(unsigned bad=1;bad<=26;bad++){
        event_fixture(1,64,1,1,3,0);activate(1);event_handoff=bad;
        assert(!graph_open()&&event_handoff_hit&&r->uncertain&&r->map_guard[0].unknown&&!r->map_guard[0].fp.restored);checks++;
        if(bad==7)event_raw(argv[5],".handoff-zero");
    }
    event_fixture(1,64,1,1,3,0);activate(1);event_image_protection=1;
    assert(graph_open()&&active_event->complete&&r->map_guard[0].fp.restored);event_raw(argv[5],".descriptor-DATA-only");checks++;
#if !defined(PCME_CLOSING_ONLY)

    event_fixture(1,64,1,1,3,0);activate(1);put(graph_pool+0xc000+8,0x80000200,4);
    assert(!graph_open()&&graph_stopped&&active_event->refusal_timer==1&&!r->map_guard[0].fp.restored);checks++;
    event_fixture(1,64,1,1,3,0);activate(1);event_mode=2;event_point=9;event_fault=16;
    assert(graph_open()&&event_hit&&active_event->complete);checks++;
    event_fixture(1,64,1,1,3,0);activate(1);event_mode=2;event_point=1;event_fault=17;
    assert(!graph_open()&&event_hit&&graph_stopped&&!r->map_guard[0].fp.restored);event_raw(argv[5],".bad-EL-source-PROT-NONE");
    assert(!mprotect(graph_core,core_mapping_bytes,PROT_READ|PROT_WRITE)&&!mprotect(graph_pool,0x40000,PROT_READ|PROT_WRITE));checks++;
#endif
#endif
    printf("{\"passed\":true,\"checks\":%u,\"SOFTWARE_only\":true,\"bytes\":%zu,\"live\":%zu,\"binding\":%zu,\"whole_constructor_or_physical\":false,\"owner_lifetime_ABA_qualification\":false}\n",checks,sizeof(struct pcme_result),sizeof(struct pcme_live),sizeof(struct pcme_binding));
    return 0;
}
