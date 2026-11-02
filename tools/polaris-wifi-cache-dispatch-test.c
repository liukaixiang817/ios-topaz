/* SOFTWARE composition of the actual release and shared deferred reader.
 * Service/AT/FP/clock leaves are explicit peers, never original instructions. */
#define POLARIS_CACHE_RELEASE_FIXTURE_ONLY 1
#include "polaris-wifi-cache-release-test.c"
#include "uefi-wifi-cache-dispatch.h"
static struct pbhd_result*dispatch_record;
static struct pbhr_live*dispatch_live;
static unsigned dispatch_attack,dispatch_byte,dispatch_level,dispatch_post,dispatch_ABA;
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
    return pbhd_call(dispatch_record,l,w,i,seal);
}
static void dispatch_setup(void)
{
    release_geometry=0;release_setup();dispatch_record=(void*)(arena+0x480000);
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
    FILE*out=fopen(argv[2],"wb");assert(out&&fwrite(release_record,1,sizeof(*release_record),out)==sizeof(*release_record)&&fwrite(dispatch_record,1,sizeof(*dispatch_record),out)==sizeof(*dispatch_record)&&!fclose(out));checks++;
    unsigned stopped=release_calls;assert(!dispatch_run()&&release_calls==stopped);checks++;
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
    printf("{\"passed\":true,\"checks\":%u,\"dispatch_bytes\":%zu,\"input_bytes\":%zu,\"live_bytes\":%zu,\"sample_bytes\":%zu,\"sample_offset\":%zu,\"API_offset\":%zu,\"digest_offset\":%zu,\"witness_bytes\":%zu,\"SOFTWARE_only\":true,\"original_FW_executed\":false,\"ABA_excluded\":false,\"wholecall_qualified\":false}\n",checks,sizeof(*dispatch_record),sizeof(dispatch_record->input),sizeof(dispatch_record->live_before),sizeof(dispatch_record->sample[0]),offsetof(struct pbhd_result,sample),offsetof(struct pbhd_result,api),offsetof(struct pbhd_result,digest),sizeof(*release_record));
    if(protected_page)assert(!mprotect(protected_page,protected_bytes,PROT_READ|PROT_WRITE));
    free(original);free(arena);free(payload_page);free(log_page);return 0;
}
