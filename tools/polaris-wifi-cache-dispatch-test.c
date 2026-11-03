/* SOFTWARE composition of the actual release and shared deferred reader.
 * Service/AT/FP/clock leaves are explicit peers, never original instructions. */
#define POLARIS_CACHE_RELEASE_FIXTURE_ONLY 1
#define POLARIS_WIFI_CACHE_TIMER_SOFTWARE_PEER 1
#include "polaris-wifi-cache-release-test.c"
#include "uefi-wifi-cache-dispatch.h"
static struct pbhd_result*dispatch_record;
static struct pbhd_timer_result*timer_record;
static struct pbhr_live*dispatch_live;
static unsigned dispatch_attack,dispatch_byte,dispatch_level,dispatch_post,dispatch_ABA;
static unsigned timer_fault,timer_slot,timer_byte,timer_reads;
static int pbhd_test_timer_regs(struct pwmc_irq_regs*p,unsigned slot)
{
    timer_reads++;uint64_t values[]={4,UINT64_C(0x12345000),1,UINT64_C(1000001000)+100*slot,19200000,UINT64_C(1000000000)+100*slot};
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
static int dispatch_guard(struct pbhr_live*l,struct pbhr_result*w,const struct pbhr_input*i,const uint8_t seal[32])
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
    return pbhd_call(dispatch_record,t,l,w,i,seal);
}
static void dispatch_setup(void)
{
    release_geometry=0;release_setup();dispatch_record=(void*)(arena+0x480000);
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
    assert(argc==3&&!posix_memalign((void**)&arena,4096,0x801000));
    assert(!posix_memalign((void**)&payload_page,4096,4096)&&!posix_memalign((void**)&log_page,4096,4096));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));unsigned checks=0;
    dispatch_setup();int ok=dispatch_run();
    if(!ok)fprintf(stderr,"dispatch error%u witness%u leaf%u/%u queue%u/%u\n",dispatch_record->error,release_record->error,dispatch_record->leaf_issued,dispatch_record->leaf_returned,dispatch_record->sample[0].head_count,dispatch_record->sample[1].head_count);
    assert(ok&&release_calls==1&&FWmaps==1&&protected_page&&dispatch_record->complete&&!dispatch_record->unknown);
    assert(dispatch_record->native_issued==15&&dispatch_record->native_returned==15&&dispatch_record->sample[0].head_count==27&&dispatch_record->sample[1].head_count==27);
    assert(timer_record->complete&&!timer_record->unknown&&timer_record->issued==3&&timer_record->returned==3&&timer_record->native_issued==15&&timer_record->native_returned==15&&timer_reads==2);
    FILE*out=fopen(argv[2],"wb");assert(out&&fwrite(release_record,1,sizeof(*release_record),out)==sizeof(*release_record)&&fwrite(dispatch_record,1,sizeof(*dispatch_record),out)==sizeof(*dispatch_record)&&fwrite(timer_record,1,sizeof(*timer_record),out)==sizeof(*timer_record)&&!fclose(out));checks++;
    unsigned stopped=release_calls;assert(!dispatch_run()&&release_calls==stopped);checks++;
#if defined(PBHD_TIMER_SMOKE_ONLY)
    printf("{\"SOFTWARE_timer_smoke_passed\":true,\"timer_bytes\":%zu}\n",sizeof(*timer_record));
    if(protected_page)assert(!mprotect(protected_page,protected_bytes,PROT_READ|PROT_WRITE));
    free(original);free(arena);free(payload_page);free(log_page);return 0;
#endif
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
    printf("{\"timer_input_bytes\":%zu,\"native_MRS_samples\":2,\"MRS_software_peer\":true,\"full_provider_and_wholecall_qualified\":false}\n",sizeof(*timer_record));
    printf("{\"passed\":true,\"checks\":%u,\"dispatch_bytes\":%zu,\"input_bytes\":%zu,\"live_bytes\":%zu,\"sample_bytes\":%zu,\"sample_offset\":%zu,\"API_offset\":%zu,\"digest_offset\":%zu,\"witness_bytes\":%zu,\"SOFTWARE_only\":true,\"original_FW_executed\":false,\"ABA_excluded\":false,\"wholecall_qualified\":false}\n",checks,sizeof(*dispatch_record),sizeof(dispatch_record->input),sizeof(dispatch_record->live_before),sizeof(dispatch_record->sample[0]),offsetof(struct pbhd_result,sample),offsetof(struct pbhd_result,api),offsetof(struct pbhd_result,digest),sizeof(*release_record));
    if(protected_page)assert(!mprotect(protected_page,protected_bytes,PROT_READ|PROT_WRITE));
    free(original);free(arena);free(payload_page);free(log_page);return 0;
}
