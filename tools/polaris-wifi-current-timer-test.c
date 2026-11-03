/* Genuine active later-provider caller. All service/AT/FP/arch and the two
 * physical-register leaves are SOFTWARE peers; original PE stays inert DATA. */
#define _DARWIN_C_SOURCE 1
#define POLARIS_WIFI_CURRENT_TIMER_INPUT 1
#define POLARIS_WIFI_CURRENT_TIMER_SOFTWARE_PEER 1
#define POLARIS_CURRENT_TIMER_FIXTURE 1
#define POLARIS_CURRENT_PROVIDER_FIXTURE_ONLY 1
#include "polaris-wifi-current-provider-test.c"
#include <sys/mman.h>
#include <unistd.h>
static struct pcmt_result(*timers)[2],*active_timer;
static struct pcmi_live*timer_caller;
static unsigned timer_calls,timer_reads,timer_fault,timer_slot,timer_byte,timer_hit,timer_entry;
static unsigned timer_late_fault,timer_late_point,timer_late_hit,timer_handoff,timer_handoff_hit,timer_handoff_arches;
static uint64_t physical_first;
static size_t core_mapping_bytes;
static void timer_memory(void)
{
    assert(!posix_memalign((void**)&arena,4096,0x1001000));
    assert(!posix_memalign((void**)&payload_data,4096,4096)&&!posix_memalign((void**)&log_data,4096,4096));
    size_t page=(size_t)sysconf(_SC_PAGESIZE);assert(page>=4096&&!(page&(page-1))&&!(0x40000%page));
    core_mapping_bytes=(PGCI_IMAGE_BYTES+page-1)&~(page-1);
    graph_core=mmap(0,core_mapping_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    graph_pool=mmap(0,0x40000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(graph_core!=MAP_FAILED&&graph_pool!=MAP_FAILED);
}
static int pcmt_test_regs(struct pwmc_irq_regs*q,unsigned slot)
{
    uint64_t physical=physical_first+10000*(timer_calls-1);
    timer_reads++;*q=(struct pwmc_irq_regs){4,(uintptr_t)provider_image[2]+0x4000,1,
        physical+19200,19200000,physical+1000*slot,63,63};
    if(timer_fault&&slot==timer_slot){timer_hit=1;
        switch(timer_fault){
        case 1:q->issued=7;q->returned=3;return 0;
        case 2:q->issued=31;q->returned=31;break;case 3:q->el=8;break;case 4:q->vbar=8;break;
        case 5:q->ctl=0;break;case 6:q->frequency=1;break;case 7:q->ticks=0;break;
        case 8:q->ticks=slot?physical+PGCD_FRESH_TICKS+1:UINT64_MAX;break;
        case 9:q->ticks=slot?physical-1:UINT64_MAX-PGCD_FRESH_TICKS+1;break;
        case 10:q->cval=UINT64_MAX;break;case 11:*cpu_flag=1;break;
        case 12:active_provider->reserved=1;break;case 13:timer_caller->parent=(void*)8;break;
        case 14:timer_caller->r=(void*)8;break;case 15:timer_caller->graph=(void*)8;break;
        case 16:active_graph->digest[0]^=1;break;case 17:put(core+0x1cdb0,1235,8);break;
        case 18:((uint8_t*)active_timer)[timer_byte]^=1;break;
        case 19:put(core+0x1c978,8,8);break;case 20:put(core+0x1dbc0,32,8);break;
        case 21:put(provider_image[0]+0x2090,0,8);break;
        case 22:active_provider->path.image[0].base=8;break;
        case 23:put(core+0x1dc00,2100,8);break;
        case 24:put(core+0x1dc00,UINT64_MAX,8);break;
        case 25:put(core+0x1c978,8,8);put(core+0x1c978,(uintptr_t)core+0x1c978,8);break;
        case 26:put(core+0x1dc00,2022000,8);break;case 27:put(core+0x1dc00,2022001,8);break;
        case 28:put(core+0x1dc00,1999,8);break;
        case 29:q->el=8;assert(!mprotect(graph_core,core_mapping_bytes,PROT_NONE)&&!mprotect(graph_pool,0x40000,PROT_NONE));break;
        default:assert(0);
        }
    }return 1;
}
static int timer_arch(void*o,struct pgcd_arch*a)
{
    int ok=provider_arch(o,a);
    if(provider_running&&timer_late_fault&&!timer_late_hit&&provider_clocks==timer_late_point){
        assert(active_timer&&active_timer->complete);timer_late_hit=1;
        switch(timer_late_fault){
        case 1:((uint8_t*)active_timer)[timer_byte]^=1;break;
        case 2:timer_caller->timer=(void*)8;break;case 3:timer_caller->timer_seal[0]^=1;break;
        default:assert(0);
        }
    }return ok;
}
static const struct pcmt_result*pcmi_parent_timer(struct pcmi_live*caller)
{
    timer_calls++;timer_caller=caller;active_timer=&timers[active_route][caller->parent->r->slot];
    struct pcmt_result(*out)[2]=timers;
    switch(timer_entry){
    case 0:break;case 1:out=(void*)8;break;case 2:out=(void*)providers;break;
    case 3:out=(void*)((uintptr_t)cpu_flag-active_route*sizeof(*timers));break;
    case 4:active_timer->reserved=1;break;default:assert(0);
    }
    return pcmt_route_capture(routes,6,out,providers,graphs,caller);
}
static int fixture_timer_minimum(const struct pgcd_context*c,unsigned slot,uint64_t*out)
{
    if(timer_handoff&&!timer_handoff_hit){
        struct pcmt_result*t=&timers[active_route][slot];timer_handoff_hit=1;timer_handoff_arches=leaf_arches;
        switch(timer_handoff){
        case 1:t->complete=0;break;case 2:t->unknown=1;break;case 3:t->reserved=1;break;
        case 4:t->issued=1;break;case 5:t->returned=1;break;case 6:t->leaf_status[1]=0;break;
        case 7:t->native_issued=7;break;case 8:t->native_returned=7;break;case 9:t->native[3]=1;break;
        case 10:t->regs[1].ticks=t->regs[0].ticks-1;break;case 11:t->sample[0].pending=32;break;
        case 12:t->sample[1].head[26][1]=8;break;case 13:t->binding.virtual_before=0;break;
        case 14:t->binding.before.r=(void*)8;break;case 15:t->binding.before.parent=(void*)8;break;
        case 16:t->binding.before.graph=(void*)8;break;case 17:t->binding.before.timer=(void*)8;break;
        case 18:t->caller_after.r=(void*)8;break;case 19:t->binding_digest[0]^=1;break;
        case 20:t->digest[0]^=1;break;case 21:t->counter_issued=0;break;case 22:t->counter_returned=0;break;
        case 23:t->counter_after[0]=t->sample[0].counter-1;break;case 24:t->counter_after[1]=UINT64_MAX;break;
        case 25:t->sample[1].counter=t->sample[0].counter-1;break;default:assert(0);
        }
        if(timer_handoff!=19&&timer_handoff!=20)ppli_sha(&t->binding,sizeof(t->binding),t->binding_digest);
        if(timer_handoff!=20)ppli_sha(t,offsetof(struct pcmt_result,digest),t->digest);
    }
    return pcmt_route_minimum(routes,6,graphs,providers,timers,c,slot,out);
}
static void timer_fixture(unsigned gcd,unsigned handlers,unsigned v3)
{
    provider_fixture(gcd,handlers,v3);timers=(void*)(arena+0xe80000);
    assert((uint8_t*)timers+6*sizeof(*timers)<arena+fixture_image_bytes);memset(timers,0,6*sizeof(*timers));
    for(unsigned k=5;k<32;k++){uint64_t at=(uintptr_t)core+0x1c928+16*k;put((void*)(uintptr_t)at,at,8);put((void*)(uintptr_t)(at+8),at,8);}
    put(core+0x1dbc0,0,8);put(core+0x1dc00,2000,8);
    original_io.arch=timer_arch;for(unsigned n=0;n<6;n++)routes[n].context->io.arch=timer_arch;
    active_timer=0;timer_caller=0;timer_calls=timer_reads=timer_fault=timer_slot=timer_byte=timer_hit=timer_entry=0;
    timer_late_fault=timer_late_point=timer_late_hit=timer_handoff=timer_handoff_hit=timer_handoff_arches=0;
    physical_first=1000000000;
}
static void timer_pair_raw(const char*base,const char*suffix)
{char name[4096];int n=snprintf(name,sizeof(name),"%s%s",base,suffix);assert(n>0&&(size_t)n<sizeof(name));FILE*f=fopen(name,"wb");
 assert(f&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&fwrite(cur,1,sizeof(*cur),f)==sizeof(*cur)&&
 fwrite(active_graph,1,sizeof(*active_graph),f)==sizeof(*active_graph)&&fwrite(active_provider,1,sizeof(*active_provider),f)==sizeof(*active_provider)&&
 fwrite(active_timer,1,sizeof(*active_timer),f)==sizeof(*active_timer)&&!fclose(f));}
int main(int argc,char**argv)
{
    assert(argc==6);timer_memory();
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");
    assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    for(unsigned k=0;k<3;k++){provider_original[k]=malloc(pwmc_irq_bindings[k].bytes);f=fopen(argv[2+k],"rb");
        assert(provider_original[k]&&f&&fread(provider_original[k],1,pwmc_irq_bindings[k].bytes,f)==pwmc_irq_bindings[k].bytes&&!fclose(f));}
    unsigned checks=0;timer_fixture(1,64,1);
    for(unsigned pass=0;pass<6;pass++){
        unsigned n=pass<5?pass+1:0;activate(n);
        if(n){int ok=graph_open();if(!ok){
                fprintf(stderr,"UNEXPECTED normal refusal route%u outer%u pcmp%u provider%u timer%u reads%u clocks%u\n",
                    n,r->error,cur->error,active_provider?active_provider->error:0,active_timer?active_timer->error:0,timer_reads,provider_clocks);
                if(active_timer)timer_pair_raw(argv[5],".unexpected-normal-refusal");
            }assert(ok);if(n<5)assert(pgcd_map_read(c,1));}
        else {for(unsigned k=0;k<4;k++){const struct pgcd_observation*q=0;assert(pgcd_query_page(c,pgcd_pages[k],&q));}assert(pgcd_finish(c));}
        for(unsigned k=0;k<(n==5?1u:2u);k++){
            const struct pcmt_result*t=&timers[n][k];const struct pcmi_result*p=&providers[n][k];
            assert(t->complete&&!t->unknown&&!t->error&&t->copied==1&&t->issued==3&&t->returned==3&&
                t->leaf_status[0]==1&&t->leaf_status[1]==1&&t->native_issued==15&&t->native_returned==15);
            assert(t->sample[0].head_count==27&&t->sample[1].head_count==27&&t->sample[0].counter==2000&&
                t->sample[1].counter==2000&&t->counter_issued==3&&t->counter_returned==3&&t->counter_after[0]==2000&&
                t->counter_after[1]==2000&&t->binding.before.r==p&&t->binding.before.parent==(void*)(uintptr_t)p->binding.parent_address);
            assert(t->binding.virtual_before==p->clock[20].raw.cpu.ticks&&p->AT_count==20&&p->arch_returned==23&&
                !p->path.finalized&&pwmc_zero(p->path.regs,sizeof(p->path.regs))&&r->map_guard[k].fp.restored);checks++;
        }
    }
    assert(timer_calls==11&&timer_reads==22&&leaf_maps==11&&pwmc_zero(&timers[5][1],sizeof(timers[5][1])));checks++;
    f=fopen(argv[5],"wb");assert(f);
    for(unsigned n=0;n<6;n++){assert(fwrite(routes[n].source,1,sizeof(*r),f)==sizeof(*r)&&fwrite(routes[n].frames,sizeof(*cur),2,f)==2&&
        fwrite(graphs[n],sizeof(*active_graph),2,f)==2&&fwrite(providers[n],sizeof(*active_provider),2,f)==2&&fwrite(timers[n],sizeof(*active_timer),2,f)==2);}
    assert(!fclose(f));
    for(unsigned v3=0;v3<2;v3++){
        timer_fixture(256,1020,v3);activate(1);assert(graph_open()&&active_timer->complete&&timer_reads==2&&
            provider_ATs==22&&provider_clocks==25&&active_provider->path.handler_count==1020);checks++;
        timer_pair_raw(argv[5],v3?".max-v3":".max-v2");
    }
#if !defined(PCMT_NORMAL_ONLY)
    for(unsigned bad=1;bad<=4;bad++){
        timer_fixture(1,64,1);activate(1);timer_entry=bad;
        assert(!graph_open()&&graph_stopped&&cur->error==7&&!timer_reads&&!r->map_guard[0].fp.restored);checks++;
    }
    for(unsigned slot=0;slot<2;slot++)for(unsigned bad=1;bad<=24;bad++){
        if(bad==23||bad==18)continue;
        timer_fixture(1,64,1);activate(1);timer_slot=slot;timer_fault=bad;
        assert(!graph_open()&&timer_hit&&graph_stopped&&active_timer->unknown&&active_provider->error==7&&
            !active_provider->complete&&!r->map_guard[0].fp.restored&&provider_clocks==21&&timer_reads==slot+1);
        assert(cur->call.map.status==0&&cur->call.map.issued==1&&cur->call.map.returned==1);
        if(slot==0&&(bad==1||bad==14||bad==22))timer_pair_raw(argv[5],bad==1?".partial":bad==14?".caller-refused":".provider-refused");checks++;
    }
    for(unsigned bit=5;bit<32;bit++){
        timer_fixture(1,64,1);activate(1);put(core+0x1dbc0,UINT64_C(1)<<bit,8);
        assert(!graph_open()&&graph_stopped&&!timer_reads&&active_timer->sample[0].pending==(UINT64_C(1)<<bit)&&
            !active_timer->sample[0].head_count&&!r->map_guard[0].fp.restored);checks++;
    }
    for(unsigned k=0;k<27;k++){
        timer_fixture(1,64,1);activate(1);put(core+0x1c928+16*(k+5),8,8);
        assert(!graph_open()&&graph_stopped&&!timer_reads&&active_timer->sample[0].head_count==k+1&&!r->map_guard[0].fp.restored);checks++;
    }
    const unsigned fields[]={0,7,8,15,16,23,32,39,336,343,392,403,404,407,408,415,416,447,448,455,456,463,464,495,
        offsetof(struct pcmt_result,binding_digest),offsetof(struct pcmt_result,sample),offsetof(struct pcmt_result,regs)+sizeof(struct pwmc_irq_regs),
        offsetof(struct pcmt_result,native),offsetof(struct pcmt_result,leaf_status),offsetof(struct pcmt_result,caller_after),
        offsetof(struct pcmt_result,counter_after),offsetof(struct pcmt_result,counter_after)+8,
        offsetof(struct pcmt_result,attempted),offsetof(struct pcmt_result,complete),offsetof(struct pcmt_result,unknown),offsetof(struct pcmt_result,error),
        offsetof(struct pcmt_result,issued),offsetof(struct pcmt_result,returned),offsetof(struct pcmt_result,native_issued),offsetof(struct pcmt_result,native_returned),
        offsetof(struct pcmt_result,copied),offsetof(struct pcmt_result,reserved),offsetof(struct pcmt_result,counter_issued),
        offsetof(struct pcmt_result,counter_returned),offsetof(struct pcmt_result,digest),sizeof(struct pcmt_result)-1};
    for(unsigned slot=0;slot<2;slot++)for(unsigned k=0;k<sizeof(fields)/sizeof(fields[0]);k++){
        unsigned at=fields[k];if(slot&&at>=offsetof(struct pcmt_result,regs)&&at<offsetof(struct pcmt_result,native))continue;
        timer_fixture(1,64,1);activate(1);timer_slot=slot;timer_fault=18;timer_byte=at;
        assert(!graph_open()&&timer_hit&&graph_stopped&&active_timer->unknown&&!r->map_guard[0].fp.restored);checks++;
    }
    for(unsigned point=22;point<=23;point++)for(unsigned bad=1;bad<=3;bad++){
        unsigned count=bad==1?sizeof(fields)/sizeof(fields[0]):1;
        for(unsigned k=0;k<count;k++){
            timer_fixture(1,64,1);activate(1);timer_late_point=point;timer_late_fault=bad;timer_byte=fields[k];
            assert(!graph_open()&&timer_late_hit&&graph_stopped&&active_provider->unknown&&!active_provider->complete&&
                timer_reads==2&&!r->map_guard[0].fp.restored);checks++;
        }
    }
    for(unsigned bad=1;bad<=25;bad++){
        timer_fixture(1,64,1);activate(1);timer_handoff=bad;
        assert(!graph_open()&&timer_handoff_hit&&leaf_arches==timer_handoff_arches&&r->uncertain&&!r->map_guard[0].fp.restored&&
            active_provider->complete&&cur->complete&&r->map[0].status==0&&r->map[0].issued==1&&r->map[0].returned==1);
        if(bad==9)timer_pair_raw(argv[5],".handoff-native");checks++;
    }
    for(unsigned epoch=0;epoch<2;epoch++){
        timer_fixture(1,64,1);activate(1);physical_first=epoch?UINT64_C(1000000000000000000):1000;
        assert(graph_open()&&active_timer->complete&&timer_reads==2);checks++;
    }
    timer_fixture(1,64,1);activate(1);timer_fault=23;
    assert(graph_open()&&timer_hit&&active_timer->sample[0].counter==2000&&active_timer->sample[1].counter==2100);checks++;
    timer_fixture(1,64,1);activate(1);timer_fault=25;
    assert(graph_open()&&timer_hit&&active_timer->complete);checks++;
    timer_fixture(1,64,1);activate(1);timer_fault=26;
    assert(graph_open()&&timer_hit&&active_timer->counter_after[0]==2022000&&active_timer->counter_after[1]==2022000);checks++;
    for(unsigned bad=27;bad<=28;bad++){
        timer_fixture(1,64,1);activate(1);timer_fault=bad;
        assert(!graph_open()&&timer_hit&&timer_reads==1&&active_timer->unknown&&!r->map_guard[0].fp.restored);checks++;
    }
    timer_fixture(1,64,1);activate(1);timer_fault=29;
    assert(!graph_open()&&timer_hit&&timer_reads==1&&active_timer->unknown&&!r->map_guard[0].fp.restored);
    timer_pair_raw(argv[5],".bad-EL-source-PROT-NONE");
    /* Host fixture access is restored only after the modeled nonreturning
     * terminal stop. No such action exists in the production failure path. */
    assert(!mprotect(graph_core,core_mapping_bytes,PROT_READ|PROT_WRITE)&&!mprotect(graph_pool,0x40000,PROT_READ|PROT_WRITE));checks++;
#endif
    printf("{\"passed\":true,\"checks\":%u,\"SOFTWARE_only\":true,\"existing_maps\":11,\"bytes\":%zu,\"binding\":%zu,\"provider_live\":%zu,\"two_six_MRS_leaves\":true,\"extra_AT_or_arch\":false,\"whole_constructor_or_physical_execution\":false,\"owner_IRQ_lifetime_qualification\":false}\n",checks,sizeof(struct pcmt_result),sizeof(struct pcmt_binding),sizeof(struct pcmi_live));
    return 0;
}
