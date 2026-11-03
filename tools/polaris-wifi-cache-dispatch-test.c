/* SOFTWARE composition of the actual release and shared deferred reader.
 * Service/AT/FP/clock leaves are explicit peers, never original instructions. */
#define POLARIS_CACHE_RELEASE_FIXTURE_ONLY 1
#define POLARIS_WIFI_CACHE_TIMER_SOFTWARE_PEER 1
struct pgcd_arch;struct ppli_at;
static int provider_arch_peer(void*,struct pgcd_arch*);
static int provider_page_peer(struct ppli_at*);
#define PBHR_FIXTURE_ARCH provider_arch_peer
#define PBHR_FIXTURE_PAGE provider_page_peer
#include "polaris-wifi-cache-release-test.c"
#include "uefi-wifi-cache-dispatch.h"
static struct pbhd_result*dispatch_record;
static struct pbhd_timer_result*timer_record;
static struct pbhi_result*provider_record;
static unsigned temporal_case;
static struct pbhr_live*dispatch_live;
static uint8_t*provider_original[3],*provider_image[3];
static unsigned provider_fault,provider_stage,provider_at,provider_clocks,provider_hit,provider_byte,provider_mode,provider_variant,provider_protect,provider_protected;
static void provider_install(void)
{
    for(unsigned k=0;k<3;k++){
        const struct pwmc_irq_binding*b=&pwmc_irq_bindings[k];provider_image[k]=arena+0x50000+0x10000*k;
        memcpy(provider_image[k],provider_original[k],b->bytes);
        for(unsigned j=0;j<b->reloc_count;j++){unsigned at=b->relocations[j];put(provider_image[k]+at,pwfi_le(provider_image[k]+at,8)+(uintptr_t)provider_image[k],8);}
        put(provider_image[k]+b->imagebase,(uintptr_t)provider_image[k],8);
    }
    uint64_t t=(uintptr_t)provider_image[0],g=(uintptr_t)provider_image[1],cpu=(uintptr_t)provider_image[2],handlers=(uintptr_t)arena+0x7a000;
    put(core+0x1cb80,t+0x2038,8);put(core+0x1c8f8,cpu+0x53d8,8);
    put(provider_image[0]+0x2058,1,8);put(provider_image[0]+0x2068,(uintptr_t)core+0x1b800,8);put(provider_image[0]+0x2070,g+0x30e0,8);
    put(provider_image[0]+0x2078,(uintptr_t)s,8);put(provider_image[0]+0x2088,(uintptr_t)core+0xcbf8,8);put(provider_image[0]+0x2090,10000,8);put(provider_image[0]+0x2098,19200,8);
    put(provider_image[1]+0x3110,(uintptr_t)core+0x1b800,8);put(provider_image[1]+0x3120,handlers,8);put(provider_image[1]+0x3128,(uintptr_t)s,8);put(provider_image[1]+0x3150,64,8);
    put(provider_image[2]+0x5420,(uintptr_t)core+0x1b800,8);put(provider_image[2]+0x5438,g+0x1acc,8);put(provider_image[2]+0x5450,(uintptr_t)s,8);
    for(unsigned k=0;k<64;k++)put((void*)(uintptr_t)(handlers+8*k),(k==18||k==19||k==26||k==29)?t+0x10c8:0,8);
}
static void provider_mutate(void)
{
    provider_hit=1;
    switch(provider_fault){
    case 1:((uint8_t*)provider_record)[provider_byte]^=1;break;
    case 2:dispatch_live->in.seed=(void*)8;break;
    case 3:release_record->fp.q8_q15[0]^=1;break;
    case 4:*native=1;break;
    case 5:put(core+0x1cb80,8,8);break;
    case 6:provider_image[0][0x1000]^=1;break;
    case 7:provider_image[0][0x2068]^=1;break;
    case 8:provider_image[1][0x30e0]^=1;break;
    case 9:put(arena+0x7a000+8*provider_byte,1,8);break;
    case 10:((uint8_t*)timer_record)[provider_byte]^=1;break;
    case 11:((uint8_t*)dispatch_record)[provider_byte]^=1;break;
    default:assert(0);
    }
}
static int provider_arch_peer(void*o,struct pgcd_arch*a)
{
    int ok=release_arch(o,a);
    if(temporal_case&&provider_record&&provider_record->closed&&a==&release_record->arch[1]){
        uint64_t floor=provider_record->clock[provider_record->arch_returned-1].raw.cpu.ticks;
        if(temporal_case==1)a->cpu.ticks=floor-1;
        if(temporal_case==2)a->cpu.ticks=release_record->arch[0].cpu.ticks;
        if(temporal_case==3)a->cpu.ticks=floor;
        if(temporal_case==4)a->cpu.ticks=floor+1;
        if(temporal_case==5)a->cpu.ticks=1000+PGCD_FRESH_TICKS;
        if(temporal_case==6)a->cpu.ticks=1000+PGCD_FRESH_TICKS+1;
    }
    if(provider_record&&provider_record->attempted){
        provider_clocks++;
        if(provider_mode==1&&provider_clocks==provider_stage){
            if(provider_fault==12){provider_hit=1;return 0;}
            if(provider_fault==13){provider_hit=1;a->cpu.ticks=1000+PGCD_FRESH_TICKS+1;}
            else if(provider_fault==14){provider_hit=1;a->cpu.ticks=999;}
            else if(provider_fault)provider_mutate();
        }
    }return ok;
}
static int provider_page_peer(struct ppli_at*a)
{
    int ok=release_page(a);
    if(provider_record&&provider_record->attempted){
        provider_at++;
        if(!provider_mode&&provider_at==provider_stage){
            if(provider_fault==12){provider_hit=1;return 0;}
            if(provider_fault==13){provider_hit=1;a->returned=0;}
            else if(provider_fault==14){provider_hit=1;a->restored^=1;}
            else if(provider_fault==15){provider_hit=1;a->par^=1;}
            else if(provider_fault)provider_mutate();
        }
    }return ok;
}
static unsigned dispatch_attack,dispatch_byte,dispatch_level,dispatch_post,dispatch_ABA;
static unsigned timer_fault,timer_slot,timer_byte,timer_reads;
static int pbhd_test_timer_regs(struct pwmc_irq_regs*p,unsigned slot)
{
    timer_reads++;uint64_t values[]={4,(uintptr_t)provider_image[2]+0x4000,1,UINT64_C(1000001000)+100*slot,19200000,UINT64_C(1000000000)+100*slot};
    for(unsigned k=0;k<6;k++){p->issued|=1u<<k;if(slot==timer_slot&&timer_fault==k+1)return 0;((uint64_t*)p)[k]=values[k];p->returned|=1u<<k;}
    if(slot==timer_slot){
        if(timer_fault==10)p->el=8;
        if(timer_fault==11)p->frequency=0;
        if(timer_fault==12)p->ctl=0;
        if(timer_fault==13)p->ctl=3;
        if(timer_fault==14)p->ctl=8;
        if(timer_fault==15)p->ticks=0;
        if(timer_fault==16)p->ticks=timer_record->regs[0].ticks-1;
        if(timer_fault==17)p->vbar+=2048;
        if(timer_fault==20)((uint8_t*)timer_record)[timer_byte]^=1;
        if(timer_fault==21)((uint8_t*)&dispatch_record->input)[timer_byte]^=1;
        if(timer_fault==22){dispatch_live->in.system=(void*)8;release_record->input.system=(void*)8;}
        if(timer_fault==23)release_record->api.status^=1;
        if(timer_fault==24)*native=1;
        if(timer_fault==25)release_record->fp.q8_q15[0]^=1;
        if(timer_fault==26)s->boot=(void*)8;
        if(timer_fault==27)return 0;
    }
    return 1;
}
static void queue_fault(void)
{
    uint8_t*head=core+0x1c928+16*dispatch_level;
    if(dispatch_attack==1)put(core+0x1dbc0,UINT64_C(1)<<dispatch_level,8);
    else if(dispatch_attack==2)put(head,(uintptr_t)head+8,8);
    else if(dispatch_attack==3)put(head+8,(uintptr_t)head+8,8);
}
static int dispatch_service(void*o,struct efi_system*system,uint64_t entry,uint64_t handles,struct pbhr_api*api)
{
    if(dispatch_attack==20)return 0;
    int ok=free_peer(o,system,entry,handles,api);
    if(provider_fault&&provider_stage==1000)provider_mutate();
    if(provider_protect){assert(!mprotect(arena+0x50000,0x30000,PROT_NONE));provider_protected=1;}
    if(timer_fault==28)((uint8_t*)timer_record)[timer_byte]^=1;
    if(dispatch_post)queue_fault();
    if(dispatch_attack==4)((uint8_t*)&dispatch_record->input)[dispatch_byte]^=1;
    if(dispatch_attack==5)((uint8_t*)&dispatch_record->live_before)[dispatch_byte]^=1;
    if(dispatch_attack==6)dispatch_live->r=(void*)8;
    if(dispatch_attack==7){release_record->input.system=(void*)8;release_record->BS[0][72]^=1;}
    if(dispatch_attack==8)s->boot=(void*)8;
    if(dispatch_attack==9)*native=1;
    if(dispatch_attack==10)release_record->fp.q8_q15[0]^=1;
    if(dispatch_attack==11)api->status=UINT64_C(0x8000000000000002);
    if(dispatch_attack==12)api->returned=0;
    if(dispatch_attack==13)((uint8_t*)s->boot)[72]^=1;
    if(dispatch_attack==14)dispatch_live->caller=(void*)8;
    if(dispatch_attack==15)dispatch_live->in.system=(void*)8;
    if(dispatch_attack==16)dispatch_live->in.seed=(void*)8;
    if(dispatch_ABA){
        /* Deliberately demonstrate the snapshot limitation, without invoking
         * a callback: temporary SOFTWARE enqueue-shaped bytes are restored. */
        uint8_t*h=core+0x1c928+16*8;put(h,(uintptr_t)h+8,8);put(core+0x1dbc0,256,8);
        put(h,(uintptr_t)h,8);put(core+0x1dbc0,0,8);
    }
    return ok;
}
static int dispatch_guard(struct pbhr_live*l,struct pbhr_result*w,const struct pbhr_input*i,const uint8_t seal[32],uint64_t*closing_ticks)
{
    dispatch_live=l;
    if(dispatch_attack==17)l->r=(void*)8;
    if(dispatch_attack==18)l->caller=(void*)8;
    if(dispatch_attack==19)l->in.system=(void*)8;
    if(dispatch_attack==21){seed->count[0]=UINT32_MAX;w->seed.count[0]=UINT32_MAX;}
    if(dispatch_attack==22){l->in.seed=(void*)8;release_input.seed=(void*)8;w->input.seed=(void*)8;}
    struct pbhd_timer_result*t=timer_record;
    switch(timer_fault){
    case 30:t=0;break;case 31:t=(void*)8;break;case 32:t=(void*)w;break;case 33:t=(void*)dispatch_record;break;
    case 34:t=(void*)seed;break;case 35:t=(void*)images;break;case 36:t=(void*)native;break;
    case 37:t=(void*)l;break;case 38:t=(void*)((uint8_t*)timer_record+1);break;
    }
    struct pbhi_result*p=provider_record;
    if(provider_mode==3){provider_hit=1;
        switch(provider_fault){
        case 20:p=0;break;case 21:p=(void*)8;break;case 22:p=(void*)w;break;
        case 23:p=(void*)dispatch_record;break;case 24:p=(void*)timer_record;break;
        case 25:p=(void*)seed;break;case 26:p=(void*)images;break;case 27:p=(void*)native;break;
        case 28:p=(void*)l;break;case 29:p=(void*)((uint8_t*)p+1);break;
        default:assert(0);
        }
    }
    if(provider_variant){
        if(provider_variant==1){put(provider_image[0]+0x2070,(uintptr_t)provider_image[1]+0x30b8,8);put(provider_image[2]+0x5438,(uintptr_t)provider_image[1]+0x1294,8);}
        if(provider_variant==2){put(provider_image[1]+0x3120,(uintptr_t)arena+0x7a100,8);put(provider_image[1]+0x3150,1020,8);
            for(unsigned k=0;k<1020;k++)put(arena+0x7a100+8*k,(k==18||k==19||k==26||k==29)?(uintptr_t)provider_image[0]+0x10c8:0,8);}
    }
    if(!pbhd_call(dispatch_record,t,p,l,w,i,seal))return 0;
    assert(p->closed&&p->complete&&!p->unknown&&p->arch_returned&&p->arch_returned<=PBHI_CLOCK_MAX);
    if(temporal_case!=14)*closing_ticks=p->clock[p->arch_returned-1].raw.cpu.ticks;
    if(temporal_case==10)*closing_ticks=0;
    if(temporal_case==11)*closing_ticks=w->arch[0].cpu.ticks-1;
    if(temporal_case==12)*closing_ticks=UINT64_MAX;
    if(temporal_case==13)*closing_ticks=1000+PGCD_FRESH_TICKS+1;
    if(temporal_case==15)*closing_ticks=timer_record->regs[1].ticks;
    return 1;
}
static void dispatch_setup(void)
{
    if(provider_protected){assert(!mprotect(arena+0x50000,0x30000,PROT_READ|PROT_WRITE));provider_protected=0;}
    provider_record=0;temporal_case=0;release_geometry=0;release_setup();dispatch_record=(void*)(arena+0x480000);
    provider_record=0;provider_fault=provider_stage=provider_at=provider_clocks=provider_hit=provider_byte=provider_mode=provider_variant=provider_protect=0;
    provider_install();provider_record=(void*)(arena+0x490000);
    timer_record=(void*)(arena+0x482000);timer_fault=timer_slot=timer_byte=timer_reads=0;
    release_input.release=dispatch_service;
    dispatch_attack=dispatch_byte=dispatch_level=dispatch_post=dispatch_ABA=0;
    put(core+0x1dbc0,0,8);put(core+0x1dc00,7000,8);
    for(unsigned level=5;level<=31;level++){
        uint8_t*h=core+0x1c928+16*level;put(h,(uintptr_t)h,8);put(h+8,(uintptr_t)h,8);
    }
}
static int dispatch_run(void)
{return pbhr_call_guarded(release_record,&release_input,dispatch_guard);}
int main(int argc,char**argv)
{
    assert(argc==6&&!posix_memalign((void**)&arena,65536,0x801000));
    assert(!posix_memalign((void**)&payload_page,4096,4096)&&!posix_memalign((void**)&log_page,4096,4096));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));unsigned checks=0;
    for(unsigned k=0;k<3;k++){const struct pwmc_irq_binding*b=&pwmc_irq_bindings[k];provider_original[k]=malloc(b->bytes);FILE*in=fopen(argv[k+2],"rb");assert(in&&provider_original[k]&&fread(provider_original[k],1,b->bytes,in)==b->bytes&&!fclose(in));}
    dispatch_setup();int ok=dispatch_run();
    if(!ok)fprintf(stderr,"dispatch error%u witness%u leaf%u/%u queue%u/%u provider%u AT%u clock%u\n",dispatch_record->error,release_record->error,dispatch_record->leaf_issued,dispatch_record->leaf_returned,dispatch_record->sample[0].head_count,dispatch_record->sample[1].head_count,provider_record->error,provider_record->AT_count,provider_record->arch_issued);
    assert(ok&&release_calls==1&&FWmaps==1&&protected_page&&dispatch_record->complete&&!dispatch_record->unknown);
    assert(dispatch_record->native_issued==15&&dispatch_record->native_returned==15&&dispatch_record->sample[0].head_count==27&&dispatch_record->sample[1].head_count==27);
    assert(timer_record->complete&&!timer_record->unknown&&timer_record->issued==3&&timer_record->returned==3&&timer_record->native_issued==15&&timer_record->native_returned==15&&timer_reads==2);
    assert(provider_record->complete&&provider_record->closed&&!provider_record->unknown);
    fprintf(stderr,"provider AT%u clocks%u source captures complete\n",provider_at,provider_clocks);
    FILE*out=fopen(argv[5],"wb");assert(out&&fwrite(release_record,1,sizeof(*release_record),out)==sizeof(*release_record)&&fwrite(dispatch_record,1,sizeof(*dispatch_record),out)==sizeof(*dispatch_record)&&fwrite(timer_record,1,sizeof(*timer_record),out)==sizeof(*timer_record)&&fwrite(provider_record,1,sizeof(*provider_record),out)==sizeof(*provider_record)&&!fclose(out));checks++;
    unsigned stopped=release_calls;assert(!dispatch_run()&&release_calls==stopped);checks++;
#if defined(PBHD_TIMER_SMOKE_ONLY)
    printf("{\"SOFTWARE_timer_smoke_passed\":true,\"timer_bytes\":%zu}\n",sizeof(*timer_record));
    if(protected_page)assert(!mprotect(protected_page,protected_bytes,PROT_READ|PROT_WRITE));
    free(original);free(arena);free(payload_page);free(log_page);return 0;
#endif
#if !defined(PBHI_NEW_CASES_ONLY) && !defined(PBHR_TEMPORAL_ONLY)
    for(unsigned post=0;post<2;post++)for(unsigned level=5;level<=31;level++)for(unsigned fault=1;fault<=3;fault++){
        dispatch_setup();dispatch_attack=fault;dispatch_level=level;dispatch_post=post;
        if(!post)queue_fault();
        assert(!dispatch_run()&&dispatch_record->unknown&&!dispatch_record->complete&&release_calls==post&&
            !release_record->fp_restore_issued&&release_record->arch_issued==1&&release_record->returned==0);
        const struct pbhd_sample*q=&dispatch_record->sample[post];
        assert(q->attempted==1&&!q->complete&&q->head_count==(fault==1?0u:level-4));
        assert(release_record->api.issued==post&&release_record->api.returned==post);
        if(!post)assert(!dispatch_record->sample[1].attempted&&!dispatch_record->leaf_issued);checks++;
    }
    for(unsigned k=0;k<sizeof(dispatch_record->input);k++){
        dispatch_setup();dispatch_attack=4;dispatch_byte=k;
        assert(!dispatch_run()&&dispatch_record->unknown&&release_calls==1&&!dispatch_record->sample[1].attempted&&!release_record->fp_restore_issued);checks++;
    }
    for(unsigned k=0;k<sizeof(dispatch_record->live_before);k++){
        dispatch_setup();dispatch_attack=5;dispatch_byte=k;
        assert(!dispatch_run()&&dispatch_record->unknown&&release_calls==1&&!dispatch_record->sample[1].attempted&&!release_record->fp_restore_issued);checks++;
    }
    for(unsigned attack=6;attack<=16;attack++){
        dispatch_setup();dispatch_attack=attack;
        assert(!dispatch_run()&&dispatch_record->unknown&&release_calls==1&&!dispatch_record->sample[1].attempted&&!release_record->fp_restore_issued);checks++;
    }
    const unsigned entry_faults[5]={17,18,19,21,22};
    for(unsigned k=0;k<5;k++){
        dispatch_setup();dispatch_attack=entry_faults[k];
        assert(!dispatch_run()&&!release_calls&&dispatch_record->unknown&&dispatch_record->error==1&&
            !dispatch_record->sample[0].attempted&&!release_record->fp_restore_issued);checks++;
        if(entry_faults[k]==17)assert(dispatch_record->live_before.r==(void*)8);
        if(entry_faults[k]==18)assert(dispatch_record->live_before.caller==(void*)8);
        if(entry_faults[k]==19)assert(dispatch_record->live_before.in.system==(void*)8);
    }
    dispatch_setup();dispatch_attack=20;assert(!dispatch_run()&&!release_calls&&dispatch_record->leaf_issued&&dispatch_record->leaf_returned&&!release_record->api.issued&&!dispatch_record->sample[1].attempted&&!release_record->fp_restore_issued);checks++;
    dispatch_setup();dispatch_ABA=1;assert(dispatch_run()&&dispatch_record->complete&&release_calls==1);checks++;
    for(unsigned slot=0;slot<2;slot++)for(unsigned leaf=1;leaf<=6;leaf++){
        dispatch_setup();timer_slot=slot;timer_fault=leaf;
        assert(!dispatch_run()&&release_calls==slot&&!release_record->fp_restore_issued&&dispatch_record->unknown&&timer_reads==slot+1);
        const struct pwmc_irq_regs*q=&timer_record->regs[slot];assert(q->issued==(1u<<leaf)-1&&q->returned==(1u<<(leaf-1))-1);
        assert(timer_record->returned==((1u<<(slot+1))-1));checks++;
    }
    for(unsigned slot=0;slot<2;slot++)for(unsigned bad=10;bad<=17;bad++){
        if(!slot&&(bad==16||bad==17))continue;
        dispatch_setup();timer_slot=slot;timer_fault=bad;
        assert(!dispatch_run()&&release_calls==slot&&dispatch_record->unknown&&!release_record->fp_restore_issued&&timer_reads==slot+1);checks++;
    }
    for(unsigned slot=0;slot<2;slot++)for(unsigned byte=0;byte<sizeof(*timer_record);byte++){
        unsigned lo=offsetof(struct pbhd_timer_result,regs)+slot*sizeof(struct pwmc_irq_regs);
        if(byte>=lo&&byte<lo+sizeof(struct pwmc_irq_regs))continue;
        dispatch_setup();timer_slot=slot;timer_fault=20;timer_byte=byte;
        assert(!dispatch_run()&&release_calls==slot&&dispatch_record->unknown&&!release_record->fp_restore_issued&&timer_reads==slot+1);checks++;
    }
    for(unsigned slot=0;slot<2;slot++)for(unsigned byte=0;byte<sizeof(dispatch_record->input);byte++){
        dispatch_setup();timer_slot=slot;timer_fault=21;timer_byte=byte;
        assert(!dispatch_run()&&release_calls==slot&&dispatch_record->unknown&&!release_record->fp_restore_issued&&timer_reads==slot+1);checks++;
    }
    for(unsigned slot=0;slot<2;slot++)for(unsigned bad=22;bad<=27;bad++){
        dispatch_setup();timer_slot=slot;timer_fault=bad;
        assert(!dispatch_run()&&release_calls==slot&&dispatch_record->unknown&&!release_record->fp_restore_issued&&timer_reads==slot+1);checks++;
    }
    for(unsigned byte=0;byte<sizeof(*timer_record);byte++){
        dispatch_setup();timer_fault=28;timer_byte=byte;
        assert(!dispatch_run()&&release_calls==1&&dispatch_record->unknown&&!dispatch_record->sample[1].attempted&&!release_record->fp_restore_issued&&timer_reads==1);checks++;
    }
    for(unsigned bad=30;bad<=38;bad++){
        dispatch_setup();timer_fault=bad;
        assert(!dispatch_run()&&!release_calls&&release_record->unknown&&!release_record->fp_restore_issued&&!timer_reads);checks++;
    }
#endif
    fprintf(stderr,"PROGRESS old composition cases retained: %u\n",checks);
#if !defined(PBHR_TEMPORAL_ONLY)
    /* New mandatory provider-input composition, keeping every old1725 case.
     * These are host RAM/AT/clock/service peers, never original FW execution. */
    for(unsigned variant=1;variant<=2;variant++){
        dispatch_setup();provider_variant=variant;assert(dispatch_run()&&provider_record->complete&&provider_record->closed&&release_calls==1);
        assert(provider_record->path.array_AT_count==(variant==2?3u:1u));checks++;
    }
    for(unsigned mode=0;mode<2;mode++)for(unsigned stage=1;stage<=(mode?23u:20u);stage++)for(unsigned fault=2;fault<=(mode?14u:15u);fault++){
        if(fault==9||fault==10||fault==11)continue;
        /* Source code/tables are not followed after release. Test the closing
         * source hash, not an unsupported post-release provider rewalk. */
        if(mode&&stage==23&&(fault==5||fault==6||fault==7||fault==8))continue;
        dispatch_setup();provider_mode=mode;provider_stage=stage;provider_fault=fault;
        int returned=dispatch_run();
        if(returned||!provider_hit)fprintf(stderr,"provider unexpected mode%u stage%u fault%u returned%d hit%u error%u/%u\n",mode,stage,fault,returned,provider_hit,dispatch_record->error,provider_record->error);
        assert(!returned&&provider_hit&&release_record->unknown&&!release_record->fp_restore_issued);
        assert(release_calls==(mode&&stage==23?1u:0u));checks++;
    }
    /* The post-release provider source remains unqualified: deliberately
     * make every provider/handler page unreadable across the closing work. */
    dispatch_setup();provider_protect=1;assert(dispatch_run()&&provider_protected&&provider_record->closed);checks++;
    const unsigned boundaries[]={0,7,8,15,16,23,24,55,56,63,64,71,72,79,432,439,440,447,448,455,
        456,463,472,527,528,631,632,2791,4000,8000,12000,12855,12856,14647,14648,19767,19768,20247,20248,20271,20272,20311,20312,20343};
    for(unsigned stage=0;stage<3;stage++)for(unsigned k=0;k<sizeof(boundaries)/sizeof(boundaries[0]);k++){
        dispatch_setup();provider_fault=1;provider_byte=boundaries[k];provider_mode=stage==1?1:0;provider_stage=stage==0?10:stage==1?10:1000;
        assert(!dispatch_run()&&provider_hit&&release_calls==(stage==2?1u:0u)&&!release_record->fp_restore_issued);
        if(stage==2)assert(!dispatch_record->sample[1].attempted&&timer_reads==1);checks++;
    }
    for(unsigned k=0;k<32;k++){
        dispatch_setup();provider_fault=9;provider_byte=k;provider_stage=1;
        assert(!dispatch_run()&&provider_hit&&!release_calls&&!release_record->fp_restore_issued);checks++;
    }
    for(unsigned output=10;output<=11;output++)for(unsigned phase=0;phase<2;phase++){
        dispatch_setup();provider_fault=output;provider_byte=7;provider_mode=phase;provider_stage=10;
        assert(!dispatch_run()&&provider_hit&&!release_calls&&!release_record->fp_restore_issued);checks++;
    }
    for(unsigned fault=20;fault<=29;fault++){
        dispatch_setup();provider_mode=3;provider_fault=fault;
        assert(!dispatch_run()&&provider_hit&&!release_calls&&!provider_at&&!timer_reads&&!release_record->fp_restore_issued);checks++;
    }
#endif
    const unsigned temporal_cases[]={1,2,3,4,5,6,10,11,12,13,14,15};
    for(unsigned k=0;k<sizeof(temporal_cases)/sizeof(temporal_cases[0]);k++){
        unsigned n=temporal_cases[k];dispatch_setup();temporal_case=n;int returned=dispatch_run();
        int expected=n==3||n==4||n==5;
        assert(returned==expected&&release_calls==1&&release_record->api.issued==1&&release_record->api.returned==1);
        if(expected)assert(release_record->complete&&release_record->fp_restore_returned==1);
        else assert(release_record->unknown&&!release_record->complete&&!release_record->fp_restore_issued&&timer_reads==2);
        if(n==1||n==2){
            uint64_t floor=provider_record->clock[provider_record->arch_returned-1].raw.cpu.ticks;
            assert(release_record->arch[1].cpu.ticks<floor&&release_record->arch[1].cpu.ticks>=release_record->arch[0].cpu.ticks);
            assert(release_record->arch_issued==2&&release_record->arch_returned==2&&release_record->error==6);
        }
        if(n==1){
            char rejected[4096];assert(snprintf(rejected,sizeof(rejected),"%s.rejected",argv[5])>0);
            FILE*bad=fopen(rejected,"wb");assert(bad&&fwrite(release_record,1,sizeof(*release_record),bad)==sizeof(*release_record)&&
                fwrite(dispatch_record,1,sizeof(*dispatch_record),bad)==sizeof(*dispatch_record)&&
                fwrite(timer_record,1,sizeof(*timer_record),bad)==sizeof(*timer_record)&&
                fwrite(provider_record,1,sizeof(*provider_record),bad)==sizeof(*provider_record)&&!fclose(bad));
        }
        checks++;
    }
    printf("{\"temporal_handoff_cases\":12,\"same_virtual_domain\":true,\"no_new_clock_call\":true,\"wholecall_qualified\":false}\n");
    printf("{\"provider_input_bytes\":%zu,\"pre_source_bound_only\":true,\"post_provider_rewalk\":false,\"wholecall_qualified\":false}\n",sizeof(*provider_record));
    printf("{\"timer_input_bytes\":%zu,\"native_MRS_samples\":2,\"MRS_software_peer\":true,\"full_provider_and_wholecall_qualified\":false}\n",sizeof(*timer_record));
    printf("{\"passed\":true,\"checks\":%u,\"dispatch_bytes\":%zu,\"input_bytes\":%zu,\"live_bytes\":%zu,\"sample_bytes\":%zu,\"sample_offset\":%zu,\"API_offset\":%zu,\"digest_offset\":%zu,\"witness_bytes\":%zu,\"SOFTWARE_only\":true,\"original_FW_executed\":false,\"ABA_excluded\":false,\"wholecall_qualified\":false}\n",checks,sizeof(*dispatch_record),sizeof(dispatch_record->input),sizeof(dispatch_record->live_before),sizeof(dispatch_record->sample[0]),offsetof(struct pbhd_result,sample),offsetof(struct pbhd_result,api),offsetof(struct pbhd_result,digest),sizeof(*release_record));
    if(protected_page)assert(!mprotect(protected_page,protected_bytes,PROT_READ|PROT_WRITE));
    free(original);free(arena);free(payload_page);free(log_page);return 0;
}
